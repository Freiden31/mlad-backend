from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.core.mail import send_mail
import uuid
from django.utils import timezone
from django.conf import settings

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    role = models.CharField(max_length=100, null=True, blank=True)
    profile_image = models.ImageField(upload_to='profile_images/', blank=True, null=True)
    date_joined = models.DateTimeField(default=timezone.now)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def generate_otp(self):
        otp = str(uuid.uuid4().int)[:6]
        self.otp = otp
        self.otp_created_at = timezone.now()
        self.save()
        return otp

    def send_otp_email(self):
        otp = self.generate_otp()
        subject = 'Account Activation OTP'
        message = f'Your OTP for account activation is: {otp}'
        from_email = settings.DEFAULT_FROM_EMAIL
        send_mail(subject, message, from_email, [self.email])

    def verify_otp(self, otp):
        if self.otp and self.otp == otp and self.otp_created_at:
            elapsed = (timezone.now() - self.otp_created_at).total_seconds()
            if elapsed < settings.OTP_EXPIRY_SECONDS:  # 24 hours = 1 day
                self.is_active = True
                self.otp = None
                self.otp_created_at = None
                self.save()
                return True
        return False

    def __str__(self):
        return f"{self.email} - {self.role}"

class Packets(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True)

    flow_key = models.CharField(max_length=255)
    prediction = models.CharField(max_length=50)

    timestamp = models.DateTimeField(auto_now_add=True)
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()

    protocol = models.FloatField()
    fwd_packet_length_min = models.FloatField()
    fwd_packet_length_std = models.FloatField(null=True, blank=True)
    bwd_packet_length_min = models.FloatField()
    flow_bytes_s = models.FloatField()

    flow_iat_min = models.FloatField()
    fwd_iat_mean = models.FloatField()
    fwd_iat_min = models.FloatField()
    bwd_iat_total = models.FloatField()
    bwd_iat_max = models.FloatField()
    bwd_iat_min = models.FloatField()
    bwd_psh_flags = models.FloatField()
    fwd_urg_flags = models.FloatField(null=True, blank=True)
    bwd_urg_flags = models.FloatField(null=True, blank=True)
    fwd_header_length = models.FloatField()
    bwd_header_length = models.FloatField()
    fwd_packets_s = models.FloatField()
    bwd_packets_s = models.FloatField()
    packet_length_min = models.FloatField()
    packet_length_variance = models.FloatField()
    fin_flag_count = models.FloatField()
    syn_flag_count = models.FloatField()
    psh_flag_count = models.FloatField()
    ack_flag_count = models.FloatField()
    urg_flag_count = models.FloatField()
    cwe_flag_count = models.FloatField()
    ece_flag_count = models.FloatField()
    down_up_ratio = models.FloatField()
    avg_fwd_segment_size = models.FloatField()
    avg_bwd_segment_size = models.FloatField()
    fwd_avg_bytes_bulk = models.FloatField()
    fwd_avg_packets_bulk = models.FloatField()
    fwd_avg_bulk_rate = models.FloatField()
    bwd_avg_bytes_bulk = models.FloatField()
    bwd_avg_packets_bulk = models.FloatField()
    bwd_avg_bulk_rate = models.FloatField()
    subflow_fwd_bytes = models.FloatField()
    subflow_bwd_bytes = models.FloatField()
    init_fwd_win_bytes = models.FloatField()
    init_bwd_win_bytes = models.FloatField()
    fwd_act_data_packets = models.FloatField()
    fwd_seg_size_min = models.FloatField()
    active_std = models.FloatField()
    active_max = models.FloatField()
    active_min = models.FloatField()
    idle_std = models.FloatField()
    idle_min = models.FloatField()

    types = models.CharField(max_length=20, blank=True)  # will store "safe" or "anomaly"

    def save(self, *args, **kwargs):
        # Automatically set type based on prediction
        self.types = "safe" if self.prediction == "safe" else "anomaly"
        super().save(*args, **kwargs)


    def __str__(self):
        return f"{self.timestamp} - {self.flow_key} - {self.prediction}"
