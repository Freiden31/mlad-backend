from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework import serializers
from .models import CustomUser, Packets
from django.core.mail import send_mail
from django.utils import timezone

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    username_field = 'email'

    def validate(self, attrs):
        data = super().validate(attrs)
        return data

class CustomUserSerializer(serializers.ModelSerializer):
    profile_image = serializers.ImageField(required=False, allow_null=True, use_url=True)

    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'password', 'profile_image', 'is_active', 'otp', 'role']
        extra_kwargs = {
            'password': {'write_only': True},
            'otp': {'write_only': True, 'required': False},
            'is_active': {'read_only': True}
        }

    def create(self, validated_data):
        profile_image = validated_data.pop('profile_image', None)
        password = validated_data.pop('password', None)

        user = CustomUser.objects.create_user(password=password, **validated_data)
        
        if profile_image:
            user.profile_image = profile_image

        user.save()
        user.send_otp_email()
        return user


    def validate_email(self, value):
        if CustomUser.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

    def update(self, instance, validated_data):
        profile_image = validated_data.pop('profile_image', None)
        for attr, value in validated_data.items():
            if attr == 'password':
                instance.set_password(value)
            else:
                setattr(instance, attr, value)
        if profile_image:
            instance.profile_image = profile_image
        instance.save()
        return instance

class OTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        
        if not user.verify_otp(data['otp']):
            raise serializers.ValidationError("Invalid or expired OTP.")
        return data

class PacketSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = Packets
        fields = [
            'id',
            'user',
            'timestamp',
            'src_ip',
            'dst_ip',
            'protocol',
            'syn_flag_count',
            'ack_flag_count',
            'fin_flag_count',
            'flow_bytes_s',
            'prediction',
        ]

class AnomalousPacketSerializer(serializers.ModelSerializer):
    user = CustomUserSerializer(read_only=True)

    class Meta:
        model = Packets
        fields = [
            'id',
            'user',
            'timestamp',
            'src_ip',
            'dst_ip',
            'prediction',
        ]