from django.db import models
import datetime as dt
# from __future__ import unicode_literals
import ipcalc

from django.db import models
from django.db.models.functions import datetime
from django.utils.timezone import utc
from django.utils.translation import ugettext_lazy as _
from django.core.cache import cache
from django.db.models.signals import post_save, post_delete
from django.utils.encoding import python_2_unicode_compatible
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from ddefender import settings

ExpireTime = settings.ExpireTime
LoginAttemps = settings.LoginAttemps


@python_2_unicode_compatible
class BlockIP(models.Model):
    network = models.CharField(_('IP address or mask'), max_length=18)
    reason_for_block = models.TextField(blank=True, null=True, help_text=_("Optional reason for block"))
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return 'BlockIP: %s' % self.network

    def get_network(self):
        return ipcalc.Network(self.network)

    class Meta:
        verbose_name = _('IPs & masks to ban')
        verbose_name_plural = _('IPs & masks to ban')


class AuditEntry(models.Model):
    action = models.CharField(max_length=64)
    ip = models.GenericIPAddressField(null=True)
    username = models.CharField(max_length=256, null=True)
    failedLoginNumber = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return '{0} - {1} - {2}'.format(self.action, self.username, self.ip)

    def __str__(self):
        return '{0} - {1} - {2}'.format(self.action, self.username, self.ip)


@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):
    ip = request.META.get('REMOTE_ADDR')
    AuditEntry.objects.create(action='user_logged_in', ip=ip, username=user.username, failedLoginNumber=0)
    ip = request.META.get('REMOTE_ADDR')
    failedobject = AuditEntry.objects.filter(action='user_login_failed', ip=ip).delete()
    try:
        if BlockIP.objects.count() > 0:
            if BlockIP.objects.filter(network=ip).all().count() > 0:
                print("its already blocked")
                lastTime = BlockIP.objects.filter(network=ip).all().latest('created_at').created_at
                diff = get_time_diff(lastTime)
                if (diff > ExpireTime):
                    BlockIP.objects.filter(network=ip).all().delete()
                    print("access granted")
            return
    except BlockIP.DoesNotExist:
        block = None


@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):
    ip = request.META.get('REMOTE_ADDR')
    AuditEntry.objects.create(action='user_logged_out', ip=ip, username=user.username)


def get_time_diff(blocked_time):
    if blocked_time:
        print("blocked time")
        print(blocked_time)
        now = datetime.datetime.utcnow().replace(tzinfo=utc)
        print(now)
        timediff = now - blocked_time
        return timediff.total_seconds() / 60


@receiver(user_login_failed)
def user_login_failed_callback(sender, request, credentials, **kwargs):
    ip = request.META.get('REMOTE_ADDR')
    try:
        if BlockIP.objects.count() > 0:
            if BlockIP.objects.filter(network=ip).all().count() > 0:
                print("its already blocked")
                lastTime = BlockIP.objects.filter(network=ip).all().latest('created_at').created_at
                diff = get_time_diff(lastTime)
                if (diff > ExpireTime):
                    BlockIP.objects.filter(network=ip).all().delete()
                    print("access granted")
            return
    except BlockIP.DoesNotExist:
        block = None
    failedLoginCount = AuditEntry.objects.filter(action='user_login_failed', ip=ip).count()
    print(failedLoginCount)
    if failedLoginCount > LoginAttemps:
        return
    if failedLoginCount == LoginAttemps:
        BlockIP.objects.create(network=ip, reason_for_block="more than 3 attemps")
        return
    AuditEntry.objects.create(action='user_login_failed', username=credentials.get('username', None), ip=ip)


def _clear_cache(sender, instance, **kwargs):
    cache.set('blockip:list', BlockIP.objects.all())


post_save.connect(_clear_cache, sender=BlockIP)
post_delete.connect(_clear_cache, sender=BlockIP)
