from hashlib import sha256
from itertools import combinations

from charm.core.math.integer import integer, isPrime, gcd, random, randomPrime, toInt
from charm.toolbox.policytree import *
from gmpy2 import gcdext

debug = False
hkey = b'ScyCree'


def d(*args):
    if debug:
        print(*args)


class RSA_abe():

    def __init__(self):
        pass

    # generate p,q and n
    def paramgen(self, secparam):
        while True:
            p, q = randomPrime(secparam), randomPrime(secparam)
            if isPrime(p) and isPrime(q) and p != q:
                N = p * q
                phi_N = (p - 1) * (q - 1)
                break
        return (p, q, N, phi_N)

    def keygen(self, r_sets, attrs, secparam=1024, params=None):
        if params:
            (p, q, N, phi_N) = self.convert(params)
        else:
            (p, q, N, phi_N) = self.paramgen(secparam)
        ts = set()
        t_count = len(r_sets)
        # 生成t
        while len(ts) < t_count:
            t = randomPrime(secparam // t_count)
            if isPrime(t) and gcd(t, phi_N) == 1:
                ts.add(int(t))
        # 转为可以索引的元组
        ts = tuple(integer(t) % phi_N for t in ts)
        # 根据禁止集生成e
        es = {k: 1 % phi_N for k in attrs}  # phi_N可模可不模，因为不会超过phi_N，后期对比效率看模不模
        for i, g in enumerate(r_sets):
            for j in g:
                es[j] = es[j] * ts[i] % phi_N
        # 生成私钥d
        ds = {}
        for k, v in es.items():
            ds[k] = v ** -1

        pk = {'N': N, 'e': es}  # strip off \phi
        sk = {'phi_N': phi_N, 'd': ds}

        return (pk, sk)

    def encrypt(self, pk, m):
        c = {}
        for k, e in pk['e'].items():
            ip = m % pk['N']  # Convert to modular integer
            c[k] = (ip ** e) % pk['N']
        return c

    def decrypt(self, pk, sk, c):
        M = (c ** (sk['d'] % sk['phi_N'])) % pk['N']
        return toInt(M)

    def convert(self, p, q, N, phi_N):
        return (integer(p), integer(q), integer(N), integer(phi_N))


def get_m_with_attr(e, c, n):
    r, u1, u2 = gcdext(e[0], e[1])
    s = [u1, u2]
    i = 2
    while r > 1:
        if i >= len(e):
            break
        r, u1, u2 = gcdext(r, e[i])
        for j in range(len(s)):
            s[j] = s[j] * u1
        s.append(u2)
        i += 1
    else:
        m = 1

        for i in range(len(s)):
            m = m * (pow(c[i], s[i], n)) % n
        return m
    return False


if __name__ == '__main__':
    # debug=True
    # 属性个数
    count = 7
    d('设置属性个数:', count)
    # 生成访问结构
    parser = PolicyParser()
    tree = parser.parse("(ONE and TWO) and (THREE or FOUR or FIVE)")
    _dictCount = {}
    parser.findDuplicates(tree, _dictCount)
    # 属性列表
    attrs = _dictCount.keys()
    r_sets = []
    # 生成禁止集
    for i in range(count - 1, 0, -1):
        g_sets = list(combinations(attrs, i))
        for g_set in g_sets:
            g_set = set(g_set)
            if not parser.prune(tree, g_set):
                for r_set in r_sets:
                    if g_set.issubset(r_set):
                        break
                else:
                    r_sets.append(g_set)
    d('禁止集:', r_sets)
    # 构建访问控制树
    # 生成e
    rsa = RSA_abe()
    d('生成密钥:')
    print(r_sets)
    pk, sk = rsa.keygen(r_sets=r_sets, attrs=attrs, secparam=1024)
    ee = list(map(int, (pk['e'].values())))
    # rsa加密，生成c，生成访问控制树
    m = 19201080 % pk['N']
    # cpabe的h掩盖m
    h = random(pk['N'])
    m = (h + m) % pk['N']
    # 加密
    c = rsa.encrypt(pk, m)
    print(c)
    # 私钥属性集
    attributes = ['ONE', 'TWO']
    c_msks = {k: int.from_bytes(sha256(k.encode() + hkey).digest(), byteorder='big') % pk['N'] for k in attributes}
    cc = []
    for k in attributes:
        cc.append((c[k]) % pk['N'])
    cc = list(map(int, cc))
    print(cc)
    # 解密
    m = get_m_with_attr(ee[:len(cc)], cc, int(pk['N']))
    print(type(m))
    print(toInt((integer(int(m)) % pk['N'] - h) % pk['N']))
