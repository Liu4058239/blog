import base64
import copy
import hmac
import json
import time

class JwtError(Exception):
    '''
    自定义Jwt异常
    '''
    def __init__(self,error_msg):
        self.error = error_msg

    def __str__(self):
        return '<JwtError error %s>' % self.error

class JWT:
    def __init__(self):
        pass

    @staticmethod
    def encode(payload,key,exp=300):
        '''
        exp:指的是有效期限
        :param payload:
        :param key:
        :param exp:
        :return:
        '''
        #创建header
        header = {'alg':'HS256', 'typ':'JWT'}
        #创建header_json串
        #separators 第一个参数表示json串中每个键值对之间用什么相连,
        #第二个参数表示key和value之间用什么相连
        #sort_keys 表示json串中按key排序输出
        header_j = json.dumps(header,separators=(',',':'),
                              sort_keys=True)
        hearer_bs = JWT.b64encode(header_j.encode())

        #创建payload
        payload = copy.deepcopy(payload)
        #创建过期时间标记
        payload['exp'] = int(time.time() + exp)
        #生成payload的json
        payload_j = json.dumps(payload,separators=(',',':'),sort_keys=True)
        #base64 payload
        payload_bs = JWT.b64encode(payload_j.encode())

        #生成sign签名
        to_sign_str = hearer_bs + b'.' + payload_bs
        #hamc new 中参数,需要用字节串bytes
        if isinstance(key,str):
            #判断key参数类型,若为字符串,则encode转换为bytes
            key = key.encode()
        hmac_obj = hmac.new(key,to_sign_str,digestmod='SHA256')
        #获取签名结果
        sign = hmac_obj.digest()
        #生成sign的base64
        sign_bs = JWT.b64encode(sign)
        return hearer_bs + b'.' + payload_bs + b'.' + sign_bs

    @staticmethod
    def b64encode(s):
        #将字节串里面的=号用空字符代替
        return base64.urlsafe_b64encode(s).replace(b'=',b'')

    @staticmethod
    def b64decode(bs):
        #将替换＝后的base64补回至原长度
        rem = len(bs) % 4
        bs += b'= ' * (4 - rem)
        return base64.urlsafe_b64decode(bs)

    @staticmethod
    def decode(token,key):
        '''
        校验token
        :param token:
        :param key:
        :return:
        '''
        #拆解token，拿出 header_bs  payload_bs  sign
        header_bs = token.split(b'.')[0]
        payload_bs = token.split(b'.')[1]
        sign = token.split(b'.')[2]

        if isinstance(key,str):
            #判断key参数类型,若为字符串,则encode转换为bytes
            key = key.encode()
        to_sign_str = header_bs + b'.' + payload_bs
        #重新计算签名
        hmac_obj = hmac.new(key,to_sign_str,digestmod='SHA256')

        #base64签名
        new_sign = JWT.b64encode(hmac_obj.digest())

        if sign != new_sign:
            # 当前传过来的token违法，则raise
            raise JwtError("Your token is  not valid ")
        #base64 decode payload_bs -- > json串的字节串
        payload_j = JWT.b64decode(payload_bs)
        print(payload_j)
        #将json串的字节串转换为字典
        payload = json.loads(payload_j.decode())
        print(payload)
        #获取过期的时间戳
        exp = payload['exp']
        now = time.time()
        #对比两个时间戳是否过期
        if now > exp:
            #时间超出有效期限，过期
            raise JwtError("Your token is expired ")
        return payload


if __name__ == "__main__":
    res = JWT.encode({'username':'cailong'},'cailong')
    print(res)

    time.sleep(3)
    print(time.time())
    rem = JWT.decode(res,'cailong')
    print(rem)