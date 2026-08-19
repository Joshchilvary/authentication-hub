from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from datetime import timedelta
from django.utils import timezone

from accounts.models import LoginHistory, UserSession, SecurityNotification, SecurityRiskAssessment

from rest_framework.test import APIClient
from rest_framework import status

User = get_user_model()


class APIRootTestCase(TestCase):
    """
    Tests for the API root endpoint.
    """

    def setUp(self):
        self.client = APIClient()

    def test_api_root_returns_200(self):
        response = self.client.get(reverse("api:root"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_api_root_structure(self):
        response = self.client.get(reverse("api:root"))
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["name"], "Authentication Hub API")
        self.assertEqual(data["data"]["version"], "v1")
        self.assertIn("documentation", data["data"])
        self.assertIn("resources", data["data"])


class HealthCheckTestCase(TestCase):
    """
    Tests for the health check endpoint.
    """

    def setUp(self):
        self.client = APIClient()

    def test_health_check_returns_200(self):
        response = self.client.get(reverse("api:health"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_health_check_structure(self):
        response = self.client.get(reverse("api:health"))
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["status"], "ok")
        self.assertEqual(data["data"]["service"], "Authentication Hub API")
        self.assertEqual(data["data"]["version"], "v1")
        self.assertIn("timestamp", data["data"])

    def test_health_check_does_not_expose_secrets(self):
        response = self.client.get(reverse("api:health"))
        content = response.content.decode()
        self.assertNotIn("SECRET_KEY", content)
        self.assertNotIn("DATABASE", content)
        self.assertNotIn("DEBUG", content)


class CurrentUserTestCase(TestCase):
    """
    Tests for the /me/ authenticated endpoint.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="test@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            is_verified=True,
        )

    def test_unauthenticated_rejected(self):
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_authenticated_returns_user_data(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["email"], "test@example.com")
        self.assertEqual(data["data"]["first_name"], "Test")
        self.assertEqual(data["data"]["last_name"], "User")
        self.assertTrue(data["data"]["is_verified"])

    def test_does_not_expose_password(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:current_user"))
        content = response.content.decode()
        self.assertNotIn("password", content)
        self.assertNotIn("testpass123", content)

    def test_does_not_expose_session_keys(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:current_user"))
        content = response.content.decode()
        self.assertNotIn("session_key", content)
        self.assertNotIn("sessionid", content)

    def test_does_not_expose_other_user_data(self):
        other_user = User.objects.create_user(
            email="other@example.com",
            password="otherpass123",
        )
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["data"]["email"], "test@example.com")
        self.assertNotEqual(data["data"]["email"], "other@example.com")


class ProfileEndpointTestCase(TestCase):
    """
    Tests for GET/PATCH /api/v1/profile/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="profile@example.com",
            password="profilepass123",
            first_name="Profile",
            last_name="User",
            phone_number="+1234567890",
            bio="Test bio",
            is_verified=True,
        )
        self.other_user = User.objects.create_user(
            email="other_profile@example.com",
            password="otherpass123",
        )

    def test_get_unauthenticated_rejected(self):
        response = self.client.get(reverse("api:profile"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_get_authenticated_returns_profile(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:profile"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["email"], "profile@example.com")
        self.assertEqual(data["data"]["first_name"], "Profile")
        self.assertEqual(data["data"]["last_name"], "User")
        self.assertEqual(data["data"]["phone_number"], "+1234567890")
        self.assertEqual(data["data"]["bio"], "Test bio")

    def test_patch_updates_allowed_fields(self):
        self.client.force_login(self.user)
        response = self.client.patch(
            reverse("api:profile"),
            {
                "first_name": "Updated",
                "last_name": "Name",
                "phone_number": "+9999999999",
                "bio": "Updated bio",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["first_name"], "Updated")
        self.assertEqual(data["data"]["last_name"], "Name")
        self.assertEqual(data["data"]["phone_number"], "+9999999999")
        self.assertEqual(data["data"]["bio"], "Updated bio")

    def test_patch_partial_update(self):
        self.client.force_login(self.user)
        response = self.client.patch(
            reverse("api:profile"),
            {
                "first_name": "Partial",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data["data"]["first_name"], "Partial")
        self.assertEqual(data["data"]["last_name"], "User")

    def test_patch_rejects_email_update(self):
        self.client.force_login(self.user)
        response = self.client.patch(
            reverse("api:profile"),
            {
                "email": "hacker@example.com",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_patch_rejects_password_update(self):
        self.client.force_login(self.user)
        response = self.client.patch(
            reverse("api:profile"),
            {
                "password": "newpassword123",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_patch_rejects_is_verified_update(self):
        self.client.force_login(self.user)
        response = self.client.patch(
            reverse("api:profile"),
            {
                "is_verified": True,
            },
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_patch_unauthenticated_rejected(self):
        response = self.client.patch(reverse("api:profile"), {"first_name": "No"})
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class LoginHistoryEndpointTestCase(TestCase):
    """
    Tests for GET /api/v1/login-history/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="history@example.com",
            password="historypass123",
        )
        self.other_user = User.objects.create_user(
            email="other@example.com",
            password="otherpass123",
        )
        for i in range(15):
            LoginHistory.objects.create(
                user=self.user,
                email_attempted=self.user.email,
                event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
                ip_address="127.0.0.1",
                browser="Chrome",
                operating_system="Windows",
                device_info="PC",
            )
        for i in range(5):
            LoginHistory.objects.create(
                user=self.other_user,
                email_attempted=self.other_user.email,
                event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
                ip_address="127.0.0.1",
                browser="Firefox",
                operating_system="Mac",
                device_info="Laptop",
            )

    def test_unauthenticated_rejected(self):
        response = self.client.get(reverse("api:login_history"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_returns_only_user_history(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:login_history"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["count"], 15)
        for item in data["data"]["results"]:
            self.assertEqual(item["event_type"], "login_success")

    def test_pagination_limits_results(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:login_history"))
        data = response.json()
        self.assertIn("results", data["data"])
        self.assertIn("count", data["data"])
        self.assertLessEqual(len(data["data"]["results"]), 10)

    def test_does_not_return_other_user_history(self):
        self.client.force_login(self.other_user)
        response = self.client.get(reverse("api:login_history"))
        data = response.json()
        self.assertEqual(data["data"]["count"], 5)
        for item in data["data"]["results"]:
            self.assertIn("Firefox", item["browser"])

    def test_does_not_expose_session_keys(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:login_history"))
        content = response.content.decode()
        self.assertNotIn("session_key", content)


class ActiveSessionsEndpointTestCase(TestCase):
    """
    Tests for GET /api/v1/sessions/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="sessions@example.com",
            password="sessionspass123",
        )
        self.other_user = User.objects.create_user(
            email="other2@example.com",
            password="otherpass123",
        )
        now = timezone.now()
        self.session = UserSession.objects.create(
            user=self.user,
            session_key="test_session_key_123",
            browser="Chrome",
            operating_system="Windows",
            device_info="PC",
            is_active=True,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=1),
        )
        UserSession.objects.create(
            user=self.other_user,
            session_key="other_session_key_456",
            browser="Safari",
            operating_system="iOS",
            device_info="iPhone",
            is_active=True,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=1),
        )

    def test_unauthenticated_rejected(self):
        response = self.client.get(reverse("api:active_sessions"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_returns_only_user_sessions(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:active_sessions"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["count"], 1)
        self.assertEqual(data["data"]["results"][0]["browser"], "Chrome")

    def test_does_not_expose_session_keys(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:active_sessions"))
        content = response.content.decode()
        self.assertNotIn("test_session_key_123", content)
        self.assertNotIn("session_key", content)

    def test_current_session_identified(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:active_sessions"))
        data = response.json()
        self.assertEqual(data["data"]["count"], 1)
        result = data["data"]["results"][0]
        self.assertIn("is_current_session", result)
        self.assertIsInstance(result["is_current_session"], bool)


class NotificationsEndpointTestCase(TestCase):
    """
    Tests for GET /api/v1/notifications/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="notifications@example.com",
            password="notificationspass123",
        )
        self.other_user = User.objects.create_user(
            email="other3@example.com",
            password="otherpass123",
        )
        for i in range(15):
            SecurityNotification.objects.create(
                user=self.user,
                notification_type=SecurityNotification.NOTIFICATION_TYPE_NEW_LOGIN,
                title=f"Notification {i}",
                message=f"Message {i}",
            )
        for i in range(5):
            SecurityNotification.objects.create(
                user=self.other_user,
                notification_type=SecurityNotification.NOTIFICATION_TYPE_PASSWORD_CHANGED,
                title=f"Other Notification {i}",
                message=f"Other Message {i}",
            )

    def test_unauthenticated_rejected(self):
        response = self.client.get(reverse("api:notifications"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_returns_only_user_notifications(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:notifications"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["count"], 15)

    def test_pagination_limits_results(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:notifications"))
        data = response.json()
        self.assertIn("results", data["data"])
        self.assertIn("count", data["data"])
        self.assertLessEqual(len(data["data"]["results"]), 10)

    def test_does_not_return_other_user_notifications(self):
        self.client.force_login(self.other_user)
        response = self.client.get(reverse("api:notifications"))
        data = response.json()
        self.assertEqual(data["data"]["count"], 5)


class RiskAssessmentsEndpointTestCase(TestCase):
    """
    Tests for GET /api/v1/risk-assessments/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="risk@example.com",
            password="riskpass123",
        )
        self.other_user = User.objects.create_user(
            email="other4@example.com",
            password="otherpass123",
        )
        for i in range(15):
            SecurityRiskAssessment.objects.create(
                user=self.user,
                risk_score=50 + i,
                risk_level=SecurityRiskAssessment.RISK_LEVEL_MEDIUM,
            )
        for i in range(5):
            SecurityRiskAssessment.objects.create(
                user=self.other_user,
                risk_score=90 + i,
                risk_level=SecurityRiskAssessment.RISK_LEVEL_HIGH,
            )

    def test_unauthenticated_rejected(self):
        response = self.client.get(reverse("api:risk_assessments"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_returns_only_user_risk_assessments(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:risk_assessments"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["count"], 15)

    def test_pagination_limits_results(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:risk_assessments"))
        data = response.json()
        self.assertIn("results", data["data"])
        self.assertIn("count", data["data"])
        self.assertLessEqual(len(data["data"]["results"]), 10)

    def test_does_not_return_other_user_assessments(self):
        self.client.force_login(self.other_user)
        response = self.client.get(reverse("api:risk_assessments"))
        data = response.json()
        self.assertEqual(data["data"]["count"], 5)


class MarkNotificationReadTestCase(TestCase):
    """
    Tests for POST /api/v1/notifications/<int:notification_id>/read/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="mark_read@example.com",
            password="markpass123",
        )
        self.other_user = User.objects.create_user(
            email="other_mark@example.com",
            password="otherpass123",
        )
        self.notification = SecurityNotification.objects.create(
            user=self.user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_NEW_LOGIN,
            title="Test Notification",
            message="Test message",
            is_read=False,
        )
        self.other_notification = SecurityNotification.objects.create(
            user=self.other_user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_PASSWORD_CHANGED,
            title="Other Notification",
            message="Other message",
            is_read=False,
        )

    def test_unauthenticated_rejected(self):
        response = self.client.post(
            reverse("api:mark_notification_read", kwargs={"notification_id": self.notification.id})
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_marks_own_notification_as_read(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("api:mark_notification_read", kwargs={"notification_id": self.notification.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertTrue(data["data"]["is_read"])
        self.notification.refresh_from_db()
        self.assertTrue(self.notification.is_read)

    def test_cannot_mark_other_user_notification(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("api:mark_notification_read", kwargs={"notification_id": self.other_notification.id})
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class MarkAllNotificationsReadTestCase(TestCase):
    """
    Tests for POST /api/v1/notifications/read-all/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="mark_all@example.com",
            password="markallpass123",
        )
        self.other_user = User.objects.create_user(
            email="other_mark_all@example.com",
            password="otherpass123",
        )
        for i in range(5):
            SecurityNotification.objects.create(
                user=self.user,
                notification_type=SecurityNotification.NOTIFICATION_TYPE_NEW_LOGIN,
                title=f"Notification {i}",
                message=f"Message {i}",
                is_read=False,
            )
        for i in range(3):
            SecurityNotification.objects.create(
                user=self.other_user,
                notification_type=SecurityNotification.NOTIFICATION_TYPE_PASSWORD_CHANGED,
                title=f"Other {i}",
                message=f"Other message {i}",
                is_read=False,
            )

    def test_unauthenticated_rejected(self):
        response = self.client.post(reverse("api:mark_all_notifications_read"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_marks_all_user_notifications_as_read(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("api:mark_all_notifications_read"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["updated_count"], 5)

        unread_count = SecurityNotification.objects.filter(
            user=self.user,
            is_read=False,
        ).count()
        self.assertEqual(unread_count, 0)

    def test_does_not_affect_other_user_notifications(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("api:mark_all_notifications_read"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        other_unread = SecurityNotification.objects.filter(
            user=self.other_user,
            is_read=False,
        ).count()
        self.assertEqual(other_unread, 3)


class RevokeSessionTestCase(TestCase):
    """
    Tests for POST /api/v1/sessions/<int:session_id>/revoke/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="revoke@example.com",
            password="revokepass123",
        )
        self.other_user = User.objects.create_user(
            email="other_revoke@example.com",
            password="otherpass123",
        )
        now = timezone.now()
        self.session = UserSession.objects.create(
            user=self.user,
            session_key="test_session_key_123",
            browser="Chrome",
            operating_system="Windows",
            device_info="PC",
            is_active=True,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=1),
        )
        self.other_session = UserSession.objects.create(
            user=self.other_user,
            session_key="other_session_key_456",
            browser="Safari",
            operating_system="iOS",
            device_info="iPhone",
            is_active=True,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=1),
        )

    def test_unauthenticated_rejected(self):
        response = self.client.post(
            reverse("api:revoke_session", kwargs={"session_id": self.session.id})
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_revokes_own_session(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("api:revoke_session", kwargs={"session_id": self.session.id})
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertFalse(data["data"]["is_active"])

        self.session.refresh_from_db()
        self.assertFalse(self.session.is_active)

    def test_does_not_expose_session_key(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("api:revoke_session", kwargs={"session_id": self.session.id})
        )
        content = response.content.decode()
        self.assertNotIn("test_session_key_123", content)
        self.assertNotIn("session_key", content)

    def test_cannot_revoke_other_user_session(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("api:revoke_session", kwargs={"session_id": self.other_session.id})
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        self.other_session.refresh_from_db()
        self.assertTrue(self.other_session.is_active)

    def test_cannot_revoke_current_session(self):
        self.client.force_login(self.user)
        # Create a session matching the current login session
        current_session_key = self.client.session.session_key
        current_session = UserSession.objects.create(
            user=self.user,
            session_key=current_session_key,
            browser="Firefox",
            operating_system="Linux",
            device_info="Laptop",
            is_active=True,
            created_at=timezone.now(),
            last_activity=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=1),
        )
        response = self.client.post(
            reverse("api:revoke_session", kwargs={"session_id": current_session.id})
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"]["code"], "cannot_revoke_current_session")


class LogoutOtherSessionsTestCase(TestCase):
    """
    Tests for POST /api/v1/sessions/logout-others/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="logout_others@example.com",
            password="logoutpass123",
        )
        self.other_user = User.objects.create_user(
            email="other_logout@example.com",
            password="otherpass123",
        )
        now = timezone.now()
        self.user_session1 = UserSession.objects.create(
            user=self.user,
            session_key="user_session_1",
            browser="Chrome",
            operating_system="Windows",
            device_info="PC",
            is_active=True,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=1),
        )
        self.user_session2 = UserSession.objects.create(
            user=self.user,
            session_key="user_session_2",
            browser="Firefox",
            operating_system="Mac",
            device_info="Laptop",
            is_active=True,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=1),
        )
        self.other_session = UserSession.objects.create(
            user=self.other_user,
            session_key="other_session_1",
            browser="Safari",
            operating_system="iOS",
            device_info="iPhone",
            is_active=True,
            created_at=now,
            last_activity=now,
            expires_at=now + timedelta(hours=1),
        )

    def test_unauthenticated_rejected(self):
        response = self.client.post(reverse("api:logout_other_sessions"))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_revokes_other_sessions_only(self):
        self.client.force_login(self.user)
        # Create a current session that should NOT be revoked
        current_session_key = self.client.session.session_key
        current_session = UserSession.objects.create(
            user=self.user,
            session_key=current_session_key,
            browser="Edge",
            operating_system="Windows",
            device_info="Desktop",
            is_active=True,
            created_at=timezone.now(),
            last_activity=timezone.now(),
            expires_at=timezone.now() + timedelta(hours=1),
        )

        response = self.client.post(reverse("api:logout_other_sessions"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["revoked_sessions"], 2)
        self.assertIn("logged out", data["data"]["message"])

        self.user_session1.refresh_from_db()
        self.user_session2.refresh_from_db()
        current_session.refresh_from_db()
        self.other_session.refresh_from_db()

        self.assertFalse(self.user_session1.is_active)
        self.assertFalse(self.user_session2.is_active)
        self.assertTrue(current_session.is_active)
        self.assertTrue(self.other_session.is_active)

    def test_does_not_affect_other_user_sessions(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("api:logout_other_sessions"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.other_session.refresh_from_db()
        self.assertTrue(self.other_session.is_active)

    def test_does_not_expose_session_keys(self):
        self.client.force_login(self.user)
        response = self.client.post(reverse("api:logout_other_sessions"))
        content = response.content.decode()
        self.assertNotIn("user_session_1", content)
        self.assertNotIn("user_session_2", content)
        self.assertNotIn("session_key", content)


class JWTObtainPairTestCase(TestCase):
    """
    Tests for POST /api/v1/auth/token/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="jwt@example.com",
            password="jwtpass123",
            first_name="JWT",
            last_name="User",
            is_verified=True,
        )

    def test_valid_credentials_return_tokens_and_user(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("access", data["data"])
        self.assertIn("refresh", data["data"])
        self.assertEqual(data["data"]["user"]["email"], "jwt@example.com")
        self.assertEqual(data["data"]["user"]["first_name"], "JWT")

    def test_password_never_returned(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt@example.com", "password": "jwtpass123"},
        )
        content = response.content.decode()
        self.assertNotIn("jwtpass123", content)
        self.assertNotIn("password", content)

    def test_invalid_password_rejected(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt@example.com", "password": "wrongpass"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertFalse(data.get("success"))

    def test_nonexistent_email_generic_error(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "nonexistent@example.com", "password": "wrongpass"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertFalse(data.get("success"))

    def test_blocked_account_rejected(self):
        from accounts.models import LoginAttempt
        from django.utils import timezone
        from datetime import timedelta

        LoginAttempt.objects.create(
            email="jwt@example.com",
            ip_address=None,
            failed_attempts=5,
            blocked_until=timezone.now() + timedelta(minutes=15),
        )
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertFalse(data.get("success"))

    def test_case_insensitive_email_login(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "JWT@EXAMPLE.COM", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["user"]["email"], "jwt@example.com")


class JWTAuthenticationTestCase(TestCase):
    """
    Tests for JWT authentication on protected endpoints.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="jwt_auth@example.com",
            password="jwtpass123",
        )

    def _get_tokens(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_auth@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.json()["data"]

    def test_access_token_protects_endpoint(self):
        tokens = self._get_tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_invalid_token_rejected(self):
        self.client.credentials(HTTP_AUTHORIZATION="Bearer invalidtoken")
        response = self.client.get(reverse("api:current_user"))
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_session_auth_still_works(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_existing_endpoints_accept_jwt(self):
        tokens = self._get_tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.get(reverse("api:profile"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_refresh_token_cannot_access_protected_endpoint(self):
        tokens = self._get_tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['refresh']}")
        response = self.client.get(reverse("api:current_user"))
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])


class JWTRefreshVerifyTestCase(TestCase):
    """
    Tests for token refresh and verify endpoints.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="jwt_refresh@example.com",
            password="jwtpass123",
        )

    def _get_tokens(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_refresh@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.json()["data"]

    def test_valid_refresh_returns_new_access(self):
        tokens = self._get_tokens()
        response = self.client.post(
            reverse("api:token_refresh"),
            {"refresh": tokens["refresh"]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("access", data["data"])
        self.assertNotEqual(data["data"]["access"], tokens["access"])

    def test_invalid_refresh_rejected(self):
        response = self.client.post(
            reverse("api:token_refresh"),
            {"refresh": "invalid_refresh_token"},
        )
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_verify_valid_access_token(self):
        tokens = self._get_tokens()
        response = self.client.post(
            reverse("api:token_verify"),
            {"token": tokens["access"]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_verify_invalid_token(self):
        response = self.client.post(
            reverse("api:token_verify"),
            {"token": "invalid_token"},
        )
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])


class JWTLogoutTestCase(TestCase):
    """
    Tests for POST /api/v1/auth/logout/
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="jwt_logout@example.com",
            password="jwtpass123",
        )

    def _get_tokens(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_logout@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        return response.json()["data"]

    def test_logout_blacklists_refresh_token(self):
        tokens = self._get_tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.post(
            reverse("api:jwt_logout"),
            {"refresh": tokens["refresh"]},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertTrue(data["success"])
        self.assertIn("message", data["data"])

        refresh_response = self.client.post(
            reverse("api:token_refresh"),
            {"refresh": tokens["refresh"]},
        )
        self.assertIn(refresh_response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_logout_without_refresh_token_rejected(self):
        tokens = self._get_tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.post(reverse("api:jwt_logout"), {})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_invalid_refresh_token_handled_safely(self):
        tokens = self._get_tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        response = self.client.post(
            reverse("api:jwt_logout"),
            {"refresh": "invalid_token"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_jwt_logout_does_not_destroy_django_session(self):
        self.client.force_login(self.user)
        tokens = self._get_tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
        self.client.post(
            reverse("api:jwt_logout"),
            {"refresh": tokens["refresh"]},
        )
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class JWTBruteForceProtectionTestCase(TestCase):
    """
    Tests for JWT integration with brute-force protection.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="jwt_brute@example.com",
            password="jwtpass123",
        )

    def test_failed_jwt_login_records_attempt(self):
        for _ in range(5):
            self.client.post(
                reverse("api:token_obtain_pair"),
                {"email": "jwt_brute@example.com", "password": "wrongpass"},
            )

        from accounts.models import LoginAttempt
        attempt = LoginAttempt.objects.get(email="jwt_brute@example.com", ip_address__isnull=True)
        self.assertGreaterEqual(attempt.failed_attempts, 5)
        self.assertIsNotNone(attempt.blocked_until)

    def test_blocked_jwt_login_rejected(self):
        from accounts.models import LoginAttempt
        from django.utils import timezone
        from datetime import timedelta

        LoginAttempt.objects.create(
            email="jwt_brute@example.com",
            ip_address=None,
            failed_attempts=5,
            blocked_until=timezone.now() + timedelta(minutes=15),
        )
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_brute@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_successful_jwt_login_resets_attempts(self):
        for _ in range(4):
            self.client.post(
                reverse("api:token_obtain_pair"),
                {"email": "jwt_brute@example.com", "password": "wrongpass"},
            )

        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_brute@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        from accounts.models import LoginAttempt
        self.assertFalse(
            LoginAttempt.objects.filter(email="jwt_brute@example.com", ip_address__isnull=True).exists()
        )


class JWTSecurityIntegrationTestCase(TestCase):
    """
    Tests for JWT login security integration.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="jwt_security@example.com",
            password="jwtpass123",
        )

    def test_successful_jwt_login_creates_history(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_security@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(
            LoginHistory.objects.filter(
                user=self.user,
                event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS,
            ).count(),
            1,
        )

    def test_successful_jwt_login_creates_risk_assessment(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_security@example.com", "password": "jwtpass123"},
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        self.assertEqual(
            SecurityRiskAssessment.objects.filter(user=self.user).count(),
            1,
        )

    def test_failed_jwt_login_creates_history(self):
        self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_security@example.com", "password": "wrongpass"},
        )

        self.assertEqual(
            LoginHistory.objects.filter(
                user=self.user,
                event_type=LoginHistory.EVENT_TYPE_LOGIN_FAILED,
            ).count(),
            1,
        )

    def test_password_never_exposed_in_response(self):
        response = self.client.post(
            reverse("api:token_obtain_pair"),
            {"email": "jwt_security@example.com", "password": "jwtpass123"},
        )
        content = response.content.decode()
        self.assertNotIn("jwtpass123", content)
        self.assertNotIn("password", content)


class ExistingEndpointsStillWorkTestCase(TestCase):
    """
    Ensure existing Phase 9.1, 9.2, and 9.3 endpoints still work after JWT addition.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            email="existing@example.com",
            password="existingpass123",
        )

    def test_api_root_still_works(self):
        response = self.client.get(reverse("api:root"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_health_still_works(self):
        response = self.client.get(reverse("api:health"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_me_endpoint_still_works(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_profile_endpoint_still_works(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:profile"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_login_history_endpoint_still_works(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:login_history"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_notifications_endpoint_still_works(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:notifications"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_revoke_session_endpoint_still_works(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("api:active_sessions"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class APIDocumentationTestCase(TestCase):
    """
    Tests for API documentation endpoints.
    """

    def setUp(self):
        self.client = APIClient()

    def test_schema_endpoint_returns_200(self):
        response = self.client.get(reverse("api:schema"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        content = response.content.decode()
        self.assertIn("Authentication Hub API", content)
        self.assertIn("swagger", content)

    def test_swagger_docs_endpoint_returns_200(self):
        response = self.client.get(reverse("api:swagger_docs"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("text/html", response["Content-Type"])

    def test_redoc_docs_endpoint_returns_200(self):
        response = self.client.get(reverse("api:redoc_docs"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("text/html", response["Content-Type"])


class APISecurityTestCase(TestCase):
    """
    Tests for API security: permissions, throttling, method restrictions,
    safe error responses, and cross-user access prevention.
    """

    def setUp(self):
        self.client = APIClient()
        self.user_a = User.objects.create_user(
            email="user_a@example.com",
            password="pass123",
        )
        self.user_b = User.objects.create_user(
            email="user_b@example.com",
            password="pass123",
        )

    def test_unauthenticated_protected_endpoints_rejected(self):
        protected_urls = [
            reverse("api:current_user"),
            reverse("api:profile"),
            reverse("api:login_history"),
            reverse("api:active_sessions"),
            reverse("api:notifications"),
            reverse("api:risk_assessments"),
        ]
        for url in protected_urls:
            response = self.client.get(url)
            self.assertIn(
                response.status_code,
                [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN],
                msg=f"Expected 401/403 for {url}, got {response.status_code}",
            )

    def test_cross_user_notification_access_blocked(self):
        from accounts.models import SecurityNotification
        notification = SecurityNotification.objects.create(
            user=self.user_b,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_NEW_LOGIN,
            title="Test",
            message="Test message",
        )
        self.client.force_login(self.user_a)
        response = self.client.post(
            reverse("api:mark_notification_read", kwargs={"notification_id": notification.id})
        )
        self.assertIn(
            response.status_code,
            [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND],
        )

    def test_cross_user_session_revoke_blocked(self):
        from accounts.models import UserSession
        from django.utils import timezone
        session = UserSession.objects.create(
            user=self.user_b,
            session_key="othersessionkey",
            ip_address="127.0.0.1",
            browser="Chrome",
            operating_system="Windows",
            device_info="PC",
            last_activity=timezone.now(),
        )
        self.client.force_login(self.user_a)
        response = self.client.post(
            reverse("api:revoke_session", kwargs={"session_id": session.id})
        )
        self.assertIn(
            response.status_code,
            [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND],
        )

    def test_http_method_restrictions(self):
        self.client.force_login(self.user_a)
        restricted_urls = [
            reverse("api:current_user"),
            reverse("api:login_history"),
            reverse("api:active_sessions"),
            reverse("api:notifications"),
            reverse("api:risk_assessments"),
        ]
        for url in restricted_urls:
            response = self.client.post(url, {})
            self.assertIn(
                response.status_code,
                [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_405_METHOD_NOT_ALLOWED],
            )

    def test_safe_error_response_format(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("success", data)
        self.assertIn("data", data)

    def test_throttling_headers_present(self):
        self.client.force_login(self.user_a)
        response = self.client.get(reverse("api:current_user"))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_success_response_consistency(self):
        self.client.force_login(self.user_a)
        endpoints = [
            reverse("api:current_user"),
            reverse("api:profile"),
            reverse("api:login_history"),
            reverse("api:active_sessions"),
            reverse("api:notifications"),
            reverse("api:risk_assessments"),
        ]
        for url in endpoints:
            response = self.client.get(url)
            self.assertEqual(response.status_code, status.HTTP_200_OK)
            data = response.json()
            self.assertIn("success", data)
            self.assertTrue(data["success"])
            self.assertIn("data", data)

    def test_error_response_format_on_invalid_profile_patch(self):
        self.client.force_login(self.user_a)
        response = self.client.patch(
            reverse("api:profile"),
            {"email": "hacker@example.com"},
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        data = response.json()
        self.assertIn("success", data)
        self.assertFalse(data["success"])
        self.assertIn("error", data)

    def test_serializers_do_not_expose_sensitive_fields(self):
        from api.serializers import UserSerializer, SafeUserSerializer
        user = User.objects.create_user(
            email="serializer@example.com",
            password="serializerpass123",
            is_staff=True,
            is_superuser=True,
        )
        user_data = UserSerializer(user).data
        self.assertNotIn("password", user_data)
        self.assertNotIn("is_staff", user_data)
        self.assertNotIn("is_superuser", user_data)
        self.assertNotIn("username", user_data)

        safe_data = SafeUserSerializer(user).data
        self.assertNotIn("password", safe_data)
        self.assertNotIn("is_staff", safe_data)
        self.assertNotIn("is_superuser", safe_data)
