import uuid

from rest_framework.response import Response
from rest_framework.views import APIView
from .models import UserInfo


class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        user = request.data.get('username')
        pwd = request.data.get('pwd')
        user_obj = UserInfo.objects.filter(username=user, pwd=pwd).first()
        if not user_obj:
            return Response({'code': 1000, 'error': '用户名货密码错误'})

        random_string = str(uuid.uuid4())
        user_obj.token = random_string
        user_obj.save()
        return Response({'code': 1000, 'data': random_string})


class OrderView(APIView):
    def get(self, request, *args, **kwargs):
        token = request.query_params.get('token')
        if not token:
            return Response({'code': 2000, 'error': '登陆之后才能访问'})
        user_obj = UserInfo.objects.filter(token=token).first()
        if not user_obj:
            return Response({'code': 2000, 'error': 'token无效'})

        return Response('订单列表')


class JwtLoginView(APIView):
    def post(self, request, *args, **kwargs):
        user = request.data.get('username')
        pwd = request.data.get('pwd')
        user_obj = UserInfo.objects.filter(username=user, pwd=pwd).first()
        if not user_obj:
            return Response({'code': 1000, 'error': '用户名货密码错误'})

        import jwt
        import datetime
        from jwt_demo.settings import SECRET_KEY
        salt = SECRET_KEY
        headers = {
            'typ': 'jwt',
            'alg': 'HS256'
        }
        # 构造payload
        payload = {
            'id': user_obj.id,  # 自定义用户ID
            'username': user_obj.username,  # 自定义用户名
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=1)  # 超时时间
        }
        token = jwt.encode(payload=payload, key=salt, algorithm="HS256", headers=headers).decode('utf-8')
        # token.decode('utf-8')
        # print(token.decode('utf-8'), type(token.decode('utf-8')))
        return Response({'code': 1000, 'data': token})


class JwtOrderView(APIView):
    def get(self, request, *args, **kwargs):
        token = request.query_params.get('token')
        # 1.切割 2.解密第二段 3.验证合法性
        import jwt
        from jwt import exceptions
        from jwt_demo.settings import SECRET_KEY
        salt = SECRET_KEY
        payload = None
        msg = None

        try:
            payload = jwt.decode(token, salt)
        except exceptions.ExpiredSignatureError:
            msg = 'token已失效'
        except jwt.DecodeError:
            msg = 'token认证失败'
        except jwt.InvalidTokenError:
            msg = '非法的token'
        if not payload:
            return Response({'code': 1003, 'error': msg})
        print(payload['id'], payload['username'])
        return Response('订单列表')


from api.utils.jwt_auth import create_token


class ProLoginView(APIView):
    # 局部取消
    # authentication_classes = []
    def post(self, request, *args, **kwargs):
        user = request.data.get('username')
        pwd = request.data.get('pwd')
        user_obj = UserInfo.objects.filter(username=user, pwd=pwd).first()
        if not user_obj:
            return Response({'code': 1000, 'error': '用户名货密码错误'})
        token = create_token({'id': user_obj.id, 'name': user_obj.username})

        return Response({'code': 1000, 'data': token})


from api.extensions.auth import JwtQueryParamsAuthentication


class ProOrderView(APIView):
    # authentication_classes = [JwtQueryParamsAuthentication, ]

    def get(self, request, *args, **kwargs):
        print(request.user)
        return Response('订单列表')
