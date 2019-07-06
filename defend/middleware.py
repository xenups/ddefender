from django.http import HttpResponseForbidden
from django.conf import settings
from django.core.cache import cache
import logging
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .models import BlockIP


def get_ip(req):
    return req.META['REMOTE_ADDR']


def is_ip_in_nets(ip, nets):
    for net in nets:
        if ip in net:
            return True
    return False


class BlockIPMiddleware(object):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_request(self, request):
        is_banned = False

        ip = get_ip(request)
        block_ips = cache.get('blockip:list')
        if block_ips is None:
            block_ips = BlockIP.objects.all()
            cache.set('blockip:list', block_ips)
        deny_ips = [i.get_network() for i in block_ips]

        for net in deny_ips:
            if ip in net:
                is_banned = True
                break

        if is_banned:
            # delete sessions when denied
            for k in request.session.keys():
                del request.session[k]
            return HttpResponseForbidden("")


log = logging.getLogger(__name__)


@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):
    ip = request.META.get('REMOTE_ADDR')

    is_banned = False
    ip = get_ip(request)
    block_ips = cache.get('blockip:list')
    if block_ips is None:
        block_ips = BlockIP.objects.all()
        cache.set('blockip:list', block_ips)
    deny_ips = [i.get_network() for i in list(block_ips)]

    for net in list(deny_ips):
        if ip in net:
            is_banned = True
            break

    if is_banned:
        # delete sessions when denied
        for k in list(request.session.keys()):
            del request.session[k]

        print("you are banned")
        return HttpResponseForbidden("")


@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):
    ip = request.META.get('REMOTE_ADDR')

    log.debug('logout user: {user} via ip: {ip}'.format(
        user=user,
        ip=ip
    ))


@receiver(user_login_failed)
def user_login_failed_callback(sender, credentials, **kwargs):
    log.warning('logout failed for: {credentials}'.format(
        credentials=credentials,
    ))
