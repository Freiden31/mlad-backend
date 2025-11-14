from django.urls import path
from .views import (
    RegisterView,
    OTPVerifyView,
    ForgotPasswordView,
    ResetPasswordView,
    DeleteAccountView,
    PacketListView,
    StartMonitoringView,
    PauseMonitoringView,
    StopMonitoringView,
    ContinueMonitoringView,
    PacketsAPIView,
    AvailableDatesAPIView,
    UserProfileView,
    AnomalousPacketListView
)

urlpatterns = [
    path("rtnc/user/register/", RegisterView.as_view(), name="register"),
    path("rtnc/verify-otp/", OTPVerifyView.as_view(), name="verify-otp"),
    path("rtnc/forgot-password/", ForgotPasswordView.as_view(), name="forgot-password"),
    path("rtnc/reset-password/<uidb64>/<token>/", ResetPasswordView.as_view(), name="reset-password"),
    path("rtnc/delete-account/", DeleteAccountView.as_view(), name="dellete-account"),
    path('rtnc/user-profile/', UserProfileView.as_view(), name='user-profile'),
    path("rtnc/start-monitoring/", StartMonitoringView.as_view(), name="start-monitoring"),
    path("rtnc/pause-monitoring/", PauseMonitoringView.as_view(), name="pause-monitoring"),
    path("rtnc/stop-monitoring/", StopMonitoringView.as_view(), name="stop-monitoring"),
    path("rtnc/continue-monitoring/", ContinueMonitoringView.as_view(), name="continue-monitoring"),
    path("rtnc/packet-list/", PacketListView.as_view(), name="packet-list"),
    path("rtnc/anomalous-packet/", AnomalousPacketListView.as_view(), name="anomalous-packet"),
    path("rtnc/packets/", PacketsAPIView.as_view(), name="packets"),
    path("rtnc/packets/dates/", AvailableDatesAPIView.as_view(), name="available_dates"),
]