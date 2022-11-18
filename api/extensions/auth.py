from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from jwt import exceptions
from django.conf import settings


class JwtQueryParamsAuthentication(BaseAuthentication):
    def authenticate(self, request):
        # 1.切割 2.解密第二段 3.验证合法性
        token = request.query_params.get('token')
        salt = settings.SECRET_KEY

        try:
            payload = jwt.decode(token, salt)
        except exceptions.ExpiredSignatureError:
            raise AuthenticationFailed({'code': 1003, 'error': 'token已失效'})
        except jwt.DecodeError:
            raise AuthenticationFailed({'code': 1003, 'error': 'token认证失败'})
        except jwt.InvalidTokenError:
            raise AuthenticationFailed({'code': 1003, 'error': '非法的token'})

        return (payload, token)
