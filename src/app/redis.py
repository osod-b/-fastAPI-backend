import redis

class RedisSession():
    __slots__ = ['redis_session', 'ttl']

    def __init__(self, password: str):
        self.redis_session = self.__initialize_session(password)

        self.ttl = None

    def __initialize_session(self, password):
        return redis.Redis(host='localhost', port=6379, db=0, decode_responses=True, max_connections=4, password=password)
    
    def hset_exp(self, name: str, ip: str, operation: str, mapping: dict, time: int):
        self.set_hash(name, ip, operation, mapping)
        self.set_hash_expirity(name, ip, operation, time)

    def set_hash_expirity(self, name: str, ip: str, operation: str, time: int):
        self.redis_session.expire(name=f'{name}={ip}[{operation}]', time=time)
        return
    
    def set_hash(self, name: str, ip: str, operation: str, mapping: dict):
        self.redis_session.hset(name=f'{name}={ip}[{operation}]', mapping=mapping)
        return
    
    def set_single_hash_value(self, name: str, ip: str, operation: str, inner_key, value):
        self.redis_session.hset(name=f'{name}={ip}[{operation}]', key=inner_key, value=value)

    def hget(self, name: str, ip: str, operation: str, inner_key):
        return self.redis_session.hget(name=f'{name}={ip}[{operation}]', key=inner_key)

    def get_whole_hash(self, name: str, ip: str, operation: str) -> dict:
        return self.redis_session.hgetall(name=f'{name}={ip}[{operation}]')
    
    def hdel(self, name: str, ip: str, operation: str):
        self.redis_session.delete(f'{name}={ip}[{operation}]')
        return
    
    # def get_item(self, name: str, ip: str, operation: str, inner_key):
    #     self.redis_session.get
    

redis_session = RedisSession(password='123')

#ttl for redis session
#PASSWORDS
#SECURITY
#HARDER CONCEPTS