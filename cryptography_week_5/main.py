import gmpy2


if __name__ == '__main__':
    p = gmpy2.mpz("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171")
    g = gmpy2.mpz("11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568")
    h = gmpy2.mpz("3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333")

    B = gmpy2.powmod(2, 20, p)

    #We try to solve this equation
    # h / (g ** x1) = (g ** B ) ** x0

    # First we build the hash table of the left operand for all value in B:
    left_hashes = {}
    print('Starting building hash table')
    for x1_val in range(B):
        left_operand = gmpy2.divm(h, gmpy2.powmod(g, x1_val, p), p)
        left_hashes[left_operand] = x1_val

    x0, x1 = 0, 0

    print('Starting checking every (g ** B ) ** x0 value ')
    # Then we check for each value if the right operand is in left_hashes,
    # meaning we found a solution for the equation
    for x0_val in range(B):
        right_operand = gmpy2.powmod(gmpy2.powmod(g, B, p), x0_val, p)
        if right_operand in left_hashes:
            print(f'Found value in hash table : {right_operand}')
            x0 = x0_val
            x1 = left_hashes[right_operand]
            break

    print(x0, x1)
    #357984 787046
    x = gmpy2.add(gmpy2.mul(x0, B), x1)
    print(f'x is equal to {x}')
    #x is equal to 375374217830





