
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rtnc.views import RegisterView, OTPVerifyView
from rtnc.jwt_views import CustomTokenObtainPairView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('admin/', admin.site.urls),
    path("rtnc/user/register/", RegisterView.as_view(), name="register"),
    path("rtnc/verify-otp/", OTPVerifyView.as_view(), name="verify-otp"),
    path("rtnc/token/", CustomTokenObtainPairView.as_view(), name="get_token"),
    path("rtnc/token/refresh/", TokenRefreshView.as_view(), name="refresh"),
    path("rtnc-auth/", include("rest_framework.urls")),
    path("", include("rtnc.urls")),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)