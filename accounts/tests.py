from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from accounts.models import User, LoginHistory, LoginAttempt, SecurityRiskAssessment, SecurityNotification, UserSession
from django.contrib.sessions.models import Session


class BruteForceProtectionTestCase(TestCase):
    """
    Tests for the brute-force protection system.
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            is_verified=True,
        )
        self.login_url = reverse('accounts:login')

    def test_normal_failed_login(self):
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'wrongpassword',
        })
        self.assertEqual(response.status_code, 200)
        form = response.context.get('form')
        self.assertIsNotNone(form)
        self.assertFormError(
            form,
            field=None,
            errors="Please enter a correct email and password. Note that both fields may be case-sensitive.",
        )
        self.assertEqual(LoginHistory.objects.filter(
            event_type=LoginHistory.EVENT_TYPE_LOGIN_FAILED
        ).count(), 1)

        attempt = LoginAttempt.objects.get(email='test@example.com', ip_address=None)
        self.assertEqual(attempt.failed_attempts, 1)
        self.assertIsNone(attempt.blocked_until)

    def test_four_failed_attempts_not_blocked(self):
        for _ in range(4):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        attempt = LoginAttempt.objects.get(email='test@example.com', ip_address=None)
        self.assertEqual(attempt.failed_attempts, 4)
        self.assertIsNone(attempt.blocked_until)

    def test_threshold_reached_blocks_account(self):
        for _ in range(5):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        attempt = LoginAttempt.objects.get(email='test@example.com', ip_address=None)
        self.assertEqual(attempt.failed_attempts, 5)
        self.assertIsNotNone(attempt.blocked_until)
        self.assertGreater(attempt.blocked_until, timezone.now())

    def test_attempt_while_blocked(self):
        attempt = LoginAttempt.objects.create(
            email='test@example.com',
            ip_address=None,
            failed_attempts=5,
            blocked_until=timezone.now() + timedelta(minutes=15),
        )

        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Too many login attempts")

        attempt.refresh_from_db()
        self.assertEqual(attempt.failed_attempts, 5)

    def test_successful_login_resets_counters(self):
        for _ in range(3):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        self.assertEqual(
            LoginAttempt.objects.filter(email='test@example.com').count(), 1
        )

        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.assertEqual(response.status_code, 302)
        self.assertFalse(
            LoginAttempt.objects.filter(email='test@example.com').exists()
        )

    def test_ip_threshold(self):
        for i in range(20):
            self.client.post(self.login_url, {
                'username': f'user{i}@example.com',
                'password': 'wrongpassword',
            })

        attempt = LoginAttempt.objects.get(email='', ip_address='127.0.0.1')
        self.assertEqual(attempt.failed_attempts, 20)
        self.assertIsNotNone(attempt.blocked_until)

    def test_expired_restriction_allows_login(self):
        attempt = LoginAttempt.objects.create(
            email='test@example.com',
            ip_address=None,
            failed_attempts=5,
            blocked_until=timezone.now() - timedelta(minutes=1),
        )

        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.assertEqual(response.status_code, 302)

    def test_case_insensitive_email(self):
        for _ in range(5):
            self.client.post(self.login_url, {
                'username': 'Test@Example.com',
                'password': 'wrongpassword',
            })

        attempt = LoginAttempt.objects.get(email='test@example.com', ip_address=None)
        self.assertEqual(attempt.failed_attempts, 5)

    def test_distributed_attack_same_email(self):
        for i in range(5):
            response = self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            }, REMOTE_ADDR=f'192.168.1.{i}')

        attempt = LoginAttempt.objects.get(email='test@example.com', ip_address=None)
        self.assertEqual(attempt.failed_attempts, 5)
        self.assertIsNotNone(attempt.blocked_until)

    def test_multiple_accounts_from_one_ip(self):
        for i in range(20):
            self.client.post(self.login_url, {
                'username': f'user{i}@example.com',
                'password': 'wrongpassword',
            })

        attempt = LoginAttempt.objects.get(email='', ip_address='127.0.0.1')
        self.assertEqual(attempt.failed_attempts, 20)

        email_attempts = LoginAttempt.objects.filter(email='test@example.com').count()
        self.assertEqual(email_attempts, 0)

    def test_admin_login_unaffected(self):
        from django.contrib.auth import authenticate

        user = User.objects.create_superuser(
            email='admin@example.com',
            password='adminpass123',
        )

        authenticated = authenticate(email='admin@example.com', password='adminpass123')
        self.assertIsNotNone(authenticated)

    def test_existing_login_history_preserved(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        success_count = LoginHistory.objects.filter(
            event_type=LoginHistory.EVENT_TYPE_LOGIN_SUCCESS
        ).count()
        self.assertEqual(success_count, 1)

        self.client.logout()

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'wrongpassword',
        })

        failed_count = LoginHistory.objects.filter(
            event_type=LoginHistory.EVENT_TYPE_LOGIN_FAILED
        ).count()
        self.assertEqual(failed_count, 1)

    def test_active_session_created_on_success(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        from accounts.models import UserSession
        self.assertEqual(
            UserSession.objects.filter(user=self.user, is_active=True).count(),
            1,
        )


class RiskScoringTestCase(TestCase):
    """
    Tests for the security risk scoring system.
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            is_verified=True,
        )
        self.login_url = reverse('accounts:login')

    def test_normal_login_produces_low_risk(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        assessment = SecurityRiskAssessment.objects.filter(user=self.user).first()
        self.assertIsNotNone(assessment)
        self.assertEqual(assessment.risk_level, SecurityRiskAssessment.RISK_LEVEL_LOW)
        self.assertLessEqual(assessment.risk_score, 29)

    def test_new_device_increases_risk(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.client.logout()

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        }, HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36')

        assessments = SecurityRiskAssessment.objects.filter(user=self.user).order_by('created_at')
        self.assertEqual(assessments.count(), 2)
        latest = assessments.last()
        self.assertGreaterEqual(latest.risk_score, 30)
        self.assertIn("New device detected", latest.risk_reasons)

    def test_new_ip_increases_risk(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.client.logout()

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        }, REMOTE_ADDR='192.168.1.100')

        assessments = SecurityRiskAssessment.objects.filter(user=self.user).order_by('created_at')
        latest = assessments.last()
        self.assertGreaterEqual(latest.risk_score, 25)
        self.assertIn("New IP address detected", latest.risk_reasons)

    def test_recent_failed_attempts_increase_risk(self):
        for _ in range(3):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        assessment = SecurityRiskAssessment.objects.filter(user=self.user).first()
        self.assertIsNotNone(assessment)
        self.assertGreaterEqual(assessment.risk_score, 30)
        self.assertIn("Recent failed login attempts detected", assessment.risk_reasons)

    def test_multiple_risk_factors_increase_score(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.client.logout()

        for _ in range(3):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        }, REMOTE_ADDR='192.168.1.200', HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36')

        assessment = SecurityRiskAssessment.objects.filter(user=self.user).order_by('-created_at').first()
        self.assertIsNotNone(assessment)
        self.assertGreaterEqual(assessment.risk_score, 55)
        self.assertIn("Multiple risk factors detected", assessment.risk_reasons)

    def test_risk_level_determined_correctly(self):
        from accounts.utils import calculate_login_risk_score

        score, level, reasons = calculate_login_risk_score(
            user=self.user,
            ip_address=None,
            user_agent_string="",
        )
        self.assertEqual(level, SecurityRiskAssessment.RISK_LEVEL_LOW)
        self.assertLessEqual(score, 29)

    def test_high_risk_creates_notification(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.client.logout()

        for _ in range(2):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        }, REMOTE_ADDR='192.168.1.250', HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36')

        assessment = SecurityRiskAssessment.objects.filter(user=self.user).order_by('-created_at').first()
        self.assertIsNotNone(assessment)
        self.assertGreaterEqual(assessment.risk_score, 60)

        notification = SecurityNotification.objects.filter(
            user=self.user,
            title__icontains="Suspicious login detected",
        ).first()
        self.assertIsNotNone(notification)

    def test_critical_risk_creates_notification(self):
        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.client.logout()

        for _ in range(3):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        }, REMOTE_ADDR='192.168.1.250', HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36')

        assessment = SecurityRiskAssessment.objects.filter(user=self.user).order_by('-created_at').first()
        self.assertIsNotNone(assessment)
        self.assertGreaterEqual(assessment.risk_score, 80)
        self.assertEqual(assessment.risk_level, SecurityRiskAssessment.RISK_LEVEL_CRITICAL)

        notification = SecurityNotification.objects.filter(
            user=self.user,
            title__icontains="Suspicious login detected",
        ).first()
        self.assertIsNotNone(notification)

    def test_risk_scoring_does_not_lock_account(self):
        for _ in range(3):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        }, REMOTE_ADDR='192.168.1.250')

        self.assertEqual(response.status_code, 302)

        assessment = SecurityRiskAssessment.objects.filter(user=self.user).first()
        self.assertIsNotNone(assessment)
        self.assertGreaterEqual(assessment.risk_score, 30)

    def test_existing_login_behavior_preserved(self):
        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })
        self.assertEqual(response.status_code, 302)

        self.assertEqual(LoginHistory.objects.filter(user=self.user).count(), 1)
        self.assertEqual(UserSession.objects.filter(user=self.user, is_active=True).count(), 1)

    def test_brute_force_protection_still_works(self):
        for _ in range(5):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Too many login attempts")

    def test_users_cannot_access_others_risk_assessments(self):
        other_user = User.objects.create_user(
            email='other@example.com',
            password='otherpass123',
            is_verified=True,
        )

        self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.client.logout()
        self.client.post(self.login_url, {
            'username': 'other@example.com',
            'password': 'otherpass123',
        })

        self.assertEqual(SecurityRiskAssessment.objects.filter(user=other_user).count(), 1)
        self.assertEqual(SecurityRiskAssessment.objects.filter(user=self.user).count(), 1)


class EmergencySecurityTestCase(TestCase):
    """
    Tests for Phase 7.5 — Emergency Security & Account Recovery.
    """

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(
            email='test@example.com',
            password='testpass123',
            is_verified=True,
        )
        self.other_user = User.objects.create_user(
            email='other@example.com',
            password='otherpass123',
            is_verified=True,
        )
        self.emergency_url = reverse('accounts:emergency_security')
        self.security_dashboard_url = reverse('accounts:security_dashboard')
        self.login_url = reverse('accounts:login')

    def _login(self, email, password):
        return self.client.post(self.login_url, {
            'username': email,
            'password': password,
        }, HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36')

    def _create_user_session(self, user, session_key):
        from django.contrib.sessions.models import Session
        from datetime import timedelta
        session = Session.objects.create(
            session_key=session_key,
            session_data='',
            expire_date=timezone.now() + timedelta(days=1),
        )
        UserSession.objects.create(
            user=user,
            session_key=session_key,
            ip_address='127.0.0.1',
            user_agent='test',
            browser='Chrome',
            operating_system='Windows',
            device_info='PC',
            last_activity=timezone.now(),
            is_active=True,
        )
        return session

    def test_unauthenticated_cannot_access_emergency_security(self):
        response = self.client.get(self.emergency_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)

    def test_get_shows_confirmation_page(self):
        self._login('test@example.com', 'testpass123')
        response = self.client.get(self.emergency_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/emergency_security.html')
        self.assertContains(response, 'Secure My Account')

    def test_post_without_csrf_is_rejected(self):
        self._login('test@example.com', 'testpass123')
        self.client.logout()
        self._login('test@example.com', 'testpass123')

        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.post(
            self.login_url,
            {'username': 'test@example.com', 'password': 'testpass123'},
        )

        response = csrf_client.post(
            self.emergency_url,
            HTTP_REFERER=self.emergency_url,
        )
        self.assertEqual(response.status_code, 403)

    def test_emergency_revokes_all_active_sessions(self):
        self._login('test@example.com', 'testpass123')
        current_session_key = self.client.session.session_key
        other_session_key = 'other_session_key_1234567890'
        self._create_user_session(self.user, other_session_key)

        self.assertEqual(
            UserSession.objects.filter(user=self.user, is_active=True).count(),
            2,
        )

        response = self.client.post(self.emergency_url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.login_url)

        self.assertEqual(
            UserSession.objects.filter(user=self.user, is_active=True).count(),
            0,
        )
        self.assertFalse(
            Session.objects.filter(session_key=current_session_key).exists()
        )
        self.assertFalse(
            Session.objects.filter(session_key=other_session_key).exists()
        )

    def test_emergency_marks_user_sessions_inactive(self):
        self._login('test@example.com', 'testpass123')
        current_session_key = self.client.session.session_key
        other_session_key = 'other_session_key_1234567890'
        self._create_user_session(self.user, other_session_key)

        self.client.post(self.emergency_url)

        self.assertFalse(
            UserSession.objects.filter(session_key=current_session_key, is_active=True).exists()
        )
        self.assertFalse(
            UserSession.objects.filter(session_key=other_session_key, is_active=True).exists()
        )

        self.assertEqual(
            UserSession.objects.filter(user=self.user).count(),
            2,
        )

    def test_emergency_does_not_affect_other_users_sessions(self):
        self._login('test@example.com', 'testpass123')
        other_session_key = 'other_user_session_1234567890'
        self._create_user_session(self.other_user, other_session_key)

        self.client.post(self.emergency_url)

        self.assertEqual(
            UserSession.objects.filter(user=self.other_user, is_active=True).count(),
            1,
        )
        self.assertTrue(
            UserSession.objects.filter(session_key=other_session_key, is_active=True).exists()
        )

    def test_emergency_creates_audit_record(self):
        self._login('test@example.com', 'testpass123')
        self.client.post(self.emergency_url, HTTP_USER_AGENT='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36')

        history = LoginHistory.objects.filter(
            user=self.user,
            event_type=LoginHistory.EVENT_TYPE_EMERGENCY_SECURITY_ACTION,
        )
        self.assertEqual(history.count(), 1)
        record = history.first()
        self.assertEqual(record.email_attempted, self.user.email)
        self.assertIsNotNone(record.ip_address)
        self.assertEqual(record.browser, 'Chrome')
        self.assertEqual(record.operating_system, 'Windows')
        self.assertEqual(record.device_info, 'PC')

    def test_emergency_creates_security_notification(self):
        self._login('test@example.com', 'testpass123')
        self.client.post(self.emergency_url)

        notification = SecurityNotification.objects.filter(
            user=self.user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_EMERGENCY_SECURITY_ACTION,
        ).first()
        self.assertIsNotNone(notification)
        self.assertIn('revoked', notification.message.lower())
        self.assertEqual(notification.ip_address, '127.0.0.1')

    def test_emergency_logs_user_out(self):
        self._login('test@example.com', 'testpass123')
        response = self.client.post(self.emergency_url)
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.login_url)

        self.assertFalse('_auth_user_id' in self.client.session)

    def test_emergency_redirects_to_login_with_message(self):
        self._login('test@example.com', 'testpass123')
        response = self.client.post(self.emergency_url, follow=True)
        self.assertRedirects(response, self.login_url, status_code=302, target_status_code=200)
        messages_list = list(response.context['messages'])
        self.assertTrue(
            any('Emergency security action completed' in str(m) for m in messages_list)
        )

    def test_get_request_does_not_revoke_sessions(self):
        self._login('test@example.com', 'testpass123')
        other_session_key = 'other_session_key_1234567890'
        self._create_user_session(self.user, other_session_key)

        self.client.get(self.emergency_url)

        self.assertEqual(
            UserSession.objects.filter(user=self.user, is_active=True).count(),
            2,
        )

    def test_emergency_preserves_login_history(self):
        self._login('test@example.com', 'testpass123')
        self.client.post(self.emergency_url)

        self.assertEqual(
            LoginHistory.objects.filter(user=self.user).count(),
            2,
        )

    def test_password_recovery_does_not_reveal_email_existence(self):
        reset_url = reverse('accounts:password_reset')
        response = self.client.post(reset_url, {'email': 'nonexistent@example.com'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('accounts:password_reset_done'))

        response = self.client.get(reverse('accounts:password_reset_done'))
        self.assertEqual(response.status_code, 200)

    def test_password_recovery_allows_password_reset(self):
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes

        self._login('test@example.com', 'testpass123')
        other_session_key = 'other_session_key_1234567890'
        self._create_user_session(self.user, other_session_key)

        self.client.logout()

        reset_url = reverse('accounts:password_reset')
        response = self.client.post(reset_url, {'email': 'test@example.com'})
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('accounts:password_reset_done'))

        self.user.refresh_from_db()

        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        confirm_url = reverse('accounts:password_reset_confirm', kwargs={'uidb64': uid, 'token': token})

        response = self.client.get(confirm_url)
        self.assertEqual(response.status_code, 302)

        response = self.client.post(response.url, {
            'new_password1': 'newsecurepass123',
            'new_password2': 'newsecurepass123',
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('accounts:password_reset_complete'))

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newsecurepass123'))

    def test_password_recovery_invalidates_other_sessions(self):
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes

        self._login('test@example.com', 'testpass123')
        other_session_key = 'other_session_key_1234567890'
        self._create_user_session(self.user, other_session_key)

        current_session_key = self.client.session.session_key
        self.client.logout()

        reset_url = reverse('accounts:password_reset')
        self.client.post(reset_url, {'email': 'test@example.com'})

        self.user.refresh_from_db()

        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        confirm_url = reverse('accounts:password_reset_confirm', kwargs={'uidb64': uid, 'token': token})

        response = self.client.get(confirm_url)
        self.assertEqual(response.status_code, 302)

        self.client.post(response.url, {
            'new_password1': 'newsecurepass123',
            'new_password2': 'newsecurepass123',
        })

        self.assertFalse(
            UserSession.objects.filter(session_key=other_session_key, is_active=True).exists()
        )

        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('newsecurepass123'))

    def test_password_recovery_creates_notification(self):
        from django.contrib.auth.tokens import default_token_generator
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes

        self._login('test@example.com', 'testpass123')
        self.client.logout()

        reset_url = reverse('accounts:password_reset')
        self.client.post(reset_url, {'email': 'test@example.com'})

        self.user.refresh_from_db()

        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        confirm_url = reverse('accounts:password_reset_confirm', kwargs={'uidb64': uid, 'token': token})

        response = self.client.get(confirm_url)
        self.assertEqual(response.status_code, 302)

        response = self.client.post(response.url, {
            'new_password1': 'newsecurepass123',
            'new_password2': 'newsecurepass123',
        })
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, reverse('accounts:password_reset_complete'))

        notification = SecurityNotification.objects.filter(
            user=self.user,
            notification_type=SecurityNotification.NOTIFICATION_TYPE_PASSWORD_RESET,
        ).first()
        self.assertIsNotNone(notification)
        self.assertIn('reset', notification.title.lower())

    def test_password_change_still_invalidates_other_sessions(self):
        self._login('test@example.com', 'testpass123')
        other_session_key = 'other_session_key_1234567890'
        self._create_user_session(self.user, other_session_key)

        response = self.client.post(reverse('accounts:password_change'), {
            'old_password': 'testpass123',
            'new_password1': 'newpass123456',
            'new_password2': 'newpass123456',
        })
        self.assertEqual(response.status_code, 302)

        self.assertFalse(
            UserSession.objects.filter(session_key=other_session_key, is_active=True).exists()
        )

        self.assertEqual(
            UserSession.objects.filter(user=self.user, is_active=True).count(),
            1,
        )

    def test_existing_login_logout_behavior_preserved(self):
        self._login('test@example.com', 'testpass123')
        self.assertEqual(int(self.client.session['_auth_user_id']), self.user.pk)

        response = self.client.get(reverse('accounts:logout'))
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, self.login_url)

        self.assertFalse('_auth_user_id' in self.client.session)

    def test_existing_active_sessions_page_works(self):
        self._login('test@example.com', 'testpass123')
        response = self.client.get(reverse('accounts:active_sessions'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/active_sessions.html')

    def test_existing_security_dashboard_works(self):
        self._login('test@example.com', 'testpass123')
        response = self.client.get(self.security_dashboard_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'accounts/security_dashboard.html')
        self.assertContains(response, 'Emergency Security')

    def test_existing_brute_force_protection_works(self):
        for _ in range(5):
            self.client.post(self.login_url, {
                'username': 'test@example.com',
                'password': 'wrongpassword',
            })

        response = self.client.post(self.login_url, {
            'username': 'test@example.com',
            'password': 'testpass123',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Too many login attempts')

    def test_existing_risk_scoring_works(self):
        self._login('test@example.com', 'testpass123')
        self.assertEqual(SecurityRiskAssessment.objects.filter(user=self.user).count(), 1)

    def test_emergency_action_cannot_target_other_user(self):
        self._login('test@example.com', 'testpass123')
        other_session_key = 'other_user_session_1234567890'
        self._create_user_session(self.other_user, other_session_key)

        self.client.post(self.emergency_url)

        self.assertEqual(
            UserSession.objects.filter(user=self.other_user, is_active=True).count(),
            1,
        )
        self.assertEqual(
            LoginHistory.objects.filter(
                user=self.user,
                event_type=LoginHistory.EVENT_TYPE_EMERGENCY_SECURITY_ACTION,
            ).count(),
            1,
        )
        self.assertEqual(
            LoginHistory.objects.filter(
                user=self.other_user,
                event_type=LoginHistory.EVENT_TYPE_EMERGENCY_SECURITY_ACTION,
            ).count(),
            0,
        )

    def test_emergency_security_dashboard_link_requires_login(self):
        response = self.client.get(self.security_dashboard_url)
        self.assertEqual(response.status_code, 302)
        self.assertIn(self.login_url, response.url)
