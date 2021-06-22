table2 = [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
          0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
          0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
          0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
          0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
          0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
          0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
          0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
          0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
          0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
          0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
          0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
          0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
          0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
          0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
          0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
          0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
          0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
          0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
          0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
          0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
          0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
          0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
          0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
          0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
          0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
          0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
          0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
          0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
          0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
          0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
          0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48,
          0xC6, 0xBA, 0xB1, 0xA3, 0x50, 0x33, 0xAA, 0x56,
          0x97, 0x91, 0x7D, 0x67, 0xDC, 0x22, 0x70, 0xB2,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

# 循环左移
def rol(val, N, n, l=256):
    result = ((val >> (N - n)) | (val << n)) & l
    return result

# 循环右移
def ror(val, N, n, l=256):
    result = ((val << (N - n)) | (val >> n)) & l
    return result

def sub_1464(data):
    b1 = data & 0xff
    b2 = (data >> 8) & 0xff
    b3 = (data >> 16) & 0xff
    b4 = (data >> 24) & 0xff
    v2 = (table2[b3] << 16) | table2[b1] | (table2[b2] << 8) | (table2[b4] << 24)
    v3 = rol(v2, 32, 12, l=0xffffffff) ^ (rol(v2, 32, 8, l=0xffffffff) ^ ror(v2, 32, 2, l=0xffffffff)) ^ ror(v2, 32, 6, l=0xffffffff)
    
    return v3


def sub_143b(data):
    n = 0
    for i in range(4, 30):
        data[i] = data[n] ^ sub_1464(data[n+1] ^ data[n+2] ^ data[n+3])
        n += 1
        
    return data

if __name__ == '__main__':
    
    input3 = "fl4g_is_s0_ug1y!"

    v10 = [ 0 ] * 30
    
    i = 0
    n = 0
    while i < len(input3):
        temp1 = (ord(input3[i]) << 24 | ord(input3[i+1]) << 16 | ord(input3[i+2]) << 8 | ord(input3[i+3]))
        temp2 = bytes.fromhex(hex(temp1)[2:])[::-1]
        v10[n] = int(''.join(['%02x' % b for b in temp2]), 16)
        i += 4
        n += 1

    result = sub_143b(v10)[-4:]
    
    v9 = []
    for j in result:
        b1 = j & 0xff
        b2 = (j >> 8) & 0xff
        b3 = (j >> 16) & 0xff
        b4 = (j >> 24) & 0xff
        
        v9.append(b4)
        v9.append(b3)
        v9.append(b2)
        v9.append(b1)
        
    print (v9)