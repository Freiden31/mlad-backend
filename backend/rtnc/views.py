from django.shortcuts import render
from rest_framework import generics, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.db.models.functions import TruncDate
from django.utils.dateparse import parse_date
from datetime import timedelta
from django.utils.timezone import now
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.core.mail import send_mail
from django.conf import settings

from .models import CustomUser, Packets
from .serializers import CustomUserSerializer, PacketSerializer, OTPSerializer, AnomalousPacketSerializer
from .monitor import (
    set_ssh_credentials,
    start_monitoring,
    disconnect_ssh,
    pause_monitoring,
    continue_monitoring,
)


class RegisterView(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({
            "message": "User registered successfully. Please check your email for OTP.",
            "user": serializer.data
        }, status=status.HTTP_201_CREATED)


class OTPVerifyView(generics.GenericAPIView):
    serializer_class = OTPSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({"message": "Account activated successfully"}, status=status.HTTP_200_OK)

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get("email")
        try:
            user = CustomUser.objects.get(email=email)
        except CustomUser.DoesNotExist:
            return Response({"detail": "Invalid email"}, status=status.HTTP_404_NOT_FOUND)

        token_generator = PasswordResetTokenGenerator()
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        reset_link = f"{settings.FRONTEND_URL}/reset-password/{uidb64}/{token}/"
        message = f"""
            To create new password\nPlease click the link below.\n\nLink:{reset_link}\n\nIf you did not reset password up you can safely ignore this message.
        """


        send_mail(
            "Password Reset Request",
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )

        return Response(
            {"success": True, "detail": "Password reset link has been sent to your email."},
            status=status.HTTP_200_OK,
        )


class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            return Response({"detail": "Invalid reset link"}, status=400)

        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"detail": "Invalid or expired reset token"}, status=400)

        new_password = request.data.get("password")
        if not new_password:
            return Response({"detail": "Password is required"}, status=400)

        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password reset successfully!"}, status=200)

class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        user = request.user
        user.delete()
        return Response({"detail": "Account successfully deleted!"}, status=status.HTTP_204_NO_CONTENT)

class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = CustomUserSerializer(user, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)



class PacketListView(generics.ListAPIView):
    serializer_class = PacketSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        last_24h = now() - timedelta(hours=24)
        return Packets.objects.filter(user=self.request.user, timestamp__gte=last_24h).order_by("-timestamp")




class AnomalousPacketListView(generics.ListAPIView):
    serializer_class = AnomalousPacketSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Packets.objects.filter(user=self.request.user).exclude(prediction__iexact="safe").order_by('-timestamp')


class PacketsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from_date = request.GET.get("from")
        to_date = request.GET.get("to")

        qs = Packets.objects.filter(user=request.user).order_by("timestamp")

        if from_date and to_date:
            try:
                f = parse_date(from_date)
                t = parse_date(to_date)
                qs = qs.filter(timestamp__date__gte=f, timestamp__date__lte=t)
            except Exception:
                return Response(
                    {"error": "Invalid date format. Use YYYY-MM-DD"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        serializer = PacketSerializer(qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AvailableDatesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        dates = (
            Packets.objects.filter(user=request.user)
            .annotate(date=TruncDate("timestamp"))
            .values_list("date", flat=True)
            .distinct()
            .order_by("date")
        )
        formatted = [d.strftime("%Y-%m-%d") for d in dates if d]
        return Response(formatted, status=status.HTTP_200_OK)


class StartMonitoringView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        host = request.data.get("host")
        username = request.data.get("username")
        password = request.data.get("password")

        try:
            set_ssh_credentials(host, username, password)
            start_monitoring(request.user)
            return Response({"message": "Monitoring started!"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PauseMonitoringView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            pause_monitoring(request.user)
            return Response({"message": "Monitoring paused!"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class StopMonitoringView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            disconnect_ssh()
            return Response({"message": "Monitoring stopped!"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ContinueMonitoringView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            continue_monitoring(request.user)
            return Response({"message": "Monitoring continued!"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)