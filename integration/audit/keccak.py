# Minimal pure-Python Keccak-256 (Ethereum variant, padding 0x01)
RC=[0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008]
ROT=[[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
M=(1<<64)-1
def rol(x,n): return ((x<<n)|(x>>(64-n)))&M if n else x
def f(A):
    for rc in RC:
        C=[A[x][0]^A[x][1]^A[x][2]^A[x][3]^A[x][4] for x in range(5)]
        D=[C[(x-1)%5]^rol(C[(x+1)%5],1) for x in range(5)]
        A=[[A[x][y]^D[x] for y in range(5)] for x in range(5)]
        B=[[0]*5 for _ in range(5)]
        for x in range(5):
            for y in range(5): B[y][(2*x+3*y)%5]=rol(A[x][y],ROT[x][y])
        A=[[B[x][y]^((~B[(x+1)%5][y])&B[(x+2)%5][y]) for y in range(5)] for x in range(5)]
        A[0][0]^=rc
    return A
def keccak256(data:bytes)->bytes:
    r=136; data=bytearray(data); data.append(1)
    while len(data)%r: data.append(0)
    data[-1]|=0x80
    A=[[0]*5 for _ in range(5)]
    for off in range(0,len(data),r):
        blk=data[off:off+r]
        for i in range(r//8):
            x,y=i%5,i//5; A[x][y]^=int.from_bytes(blk[8*i:8*i+8],'little')
        A=f(A)
    out=b''.join(A[i%5][i//5].to_bytes(8,'little') for i in range(4))
    return out
if __name__=='__main__':
    import sys
    assert keccak256(b'abc').hex()=='4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45'
    print('0x'+keccak256(open(sys.argv[1],'rb').read()).hex())
