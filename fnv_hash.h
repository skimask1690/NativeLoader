// -------------------- FNV-1a string hashing --------------------
#define FNV32_OFFSET 0x811c9dc5
#define FNV32_PRIME 0x01000193

typedef const unsigned long HASH_t;

#define FNV_STEP(c,h) (((h) ^ (unsigned char)(c)) * FNV32_PRIME)

// Unrolled macros for up to 64 characters
#define FNV_ITER_0(s,h)  FNV_STEP((s)[0],  h)
#define FNV_ITER_1(s,h)  FNV_STEP((s)[1],  FNV_ITER_0(s,h))
#define FNV_ITER_2(s,h)  FNV_STEP((s)[2],  FNV_ITER_1(s,h))
#define FNV_ITER_3(s,h)  FNV_STEP((s)[3],  FNV_ITER_2(s,h))
#define FNV_ITER_4(s,h)  FNV_STEP((s)[4],  FNV_ITER_3(s,h))
#define FNV_ITER_5(s,h)  FNV_STEP((s)[5],  FNV_ITER_4(s,h))
#define FNV_ITER_6(s,h)  FNV_STEP((s)[6],  FNV_ITER_5(s,h))
#define FNV_ITER_7(s,h)  FNV_STEP((s)[7],  FNV_ITER_6(s,h))
#define FNV_ITER_8(s,h)  FNV_STEP((s)[8],  FNV_ITER_7(s,h))
#define FNV_ITER_9(s,h)  FNV_STEP((s)[9],  FNV_ITER_8(s,h))
#define FNV_ITER_10(s,h) FNV_STEP((s)[10], FNV_ITER_9(s,h))
#define FNV_ITER_11(s,h) FNV_STEP((s)[11], FNV_ITER_10(s,h))
#define FNV_ITER_12(s,h) FNV_STEP((s)[12], FNV_ITER_11(s,h))
#define FNV_ITER_13(s,h) FNV_STEP((s)[13], FNV_ITER_12(s,h))
#define FNV_ITER_14(s,h) FNV_STEP((s)[14], FNV_ITER_13(s,h))
#define FNV_ITER_15(s,h) FNV_STEP((s)[15], FNV_ITER_14(s,h))
#define FNV_ITER_16(s,h) FNV_STEP((s)[16], FNV_ITER_15(s,h))
#define FNV_ITER_17(s,h) FNV_STEP((s)[17], FNV_ITER_16(s,h))
#define FNV_ITER_18(s,h) FNV_STEP((s)[18], FNV_ITER_17(s,h))
#define FNV_ITER_19(s,h) FNV_STEP((s)[19], FNV_ITER_18(s,h))
#define FNV_ITER_20(s,h) FNV_STEP((s)[20], FNV_ITER_19(s,h))
#define FNV_ITER_21(s,h) FNV_STEP((s)[21], FNV_ITER_20(s,h))
#define FNV_ITER_22(s,h) FNV_STEP((s)[22], FNV_ITER_21(s,h))
#define FNV_ITER_23(s,h) FNV_STEP((s)[23], FNV_ITER_22(s,h))
#define FNV_ITER_24(s,h) FNV_STEP((s)[24], FNV_ITER_23(s,h))
#define FNV_ITER_25(s,h) FNV_STEP((s)[25], FNV_ITER_24(s,h))
#define FNV_ITER_26(s,h) FNV_STEP((s)[26], FNV_ITER_25(s,h))
#define FNV_ITER_27(s,h) FNV_STEP((s)[27], FNV_ITER_26(s,h))
#define FNV_ITER_28(s,h) FNV_STEP((s)[28], FNV_ITER_27(s,h))
#define FNV_ITER_29(s,h) FNV_STEP((s)[29], FNV_ITER_28(s,h))
#define FNV_ITER_30(s,h) FNV_STEP((s)[30], FNV_ITER_29(s,h))
#define FNV_ITER_31(s,h) FNV_STEP((s)[31], FNV_ITER_30(s,h))
#define FNV_ITER_32(s,h) FNV_STEP((s)[32], FNV_ITER_31(s,h))
#define FNV_ITER_33(s,h) FNV_STEP((s)[33], FNV_ITER_32(s,h))
#define FNV_ITER_34(s,h) FNV_STEP((s)[34], FNV_ITER_33(s,h))
#define FNV_ITER_35(s,h) FNV_STEP((s)[35], FNV_ITER_34(s,h))
#define FNV_ITER_36(s,h) FNV_STEP((s)[36], FNV_ITER_35(s,h))
#define FNV_ITER_37(s,h) FNV_STEP((s)[37], FNV_ITER_36(s,h))
#define FNV_ITER_38(s,h) FNV_STEP((s)[38], FNV_ITER_37(s,h))
#define FNV_ITER_39(s,h) FNV_STEP((s)[39], FNV_ITER_38(s,h))
#define FNV_ITER_40(s,h) FNV_STEP((s)[40], FNV_ITER_39(s,h))
#define FNV_ITER_41(s,h) FNV_STEP((s)[41], FNV_ITER_40(s,h))
#define FNV_ITER_42(s,h) FNV_STEP((s)[42], FNV_ITER_41(s,h))
#define FNV_ITER_43(s,h) FNV_STEP((s)[43], FNV_ITER_42(s,h))
#define FNV_ITER_44(s,h) FNV_STEP((s)[44], FNV_ITER_43(s,h))
#define FNV_ITER_45(s,h) FNV_STEP((s)[45], FNV_ITER_44(s,h))
#define FNV_ITER_46(s,h) FNV_STEP((s)[46], FNV_ITER_45(s,h))
#define FNV_ITER_47(s,h) FNV_STEP((s)[47], FNV_ITER_46(s,h))
#define FNV_ITER_48(s,h) FNV_STEP((s)[48], FNV_ITER_47(s,h))
#define FNV_ITER_49(s,h) FNV_STEP((s)[49], FNV_ITER_48(s,h))
#define FNV_ITER_50(s,h) FNV_STEP((s)[50], FNV_ITER_49(s,h))
#define FNV_ITER_51(s,h) FNV_STEP((s)[51], FNV_ITER_50(s,h))
#define FNV_ITER_52(s,h) FNV_STEP((s)[52], FNV_ITER_51(s,h))
#define FNV_ITER_53(s,h) FNV_STEP((s)[53], FNV_ITER_52(s,h))
#define FNV_ITER_54(s,h) FNV_STEP((s)[54], FNV_ITER_53(s,h))
#define FNV_ITER_55(s,h) FNV_STEP((s)[55], FNV_ITER_54(s,h))
#define FNV_ITER_56(s,h) FNV_STEP((s)[56], FNV_ITER_55(s,h))
#define FNV_ITER_57(s,h) FNV_STEP((s)[57], FNV_ITER_56(s,h))
#define FNV_ITER_58(s,h) FNV_STEP((s)[58], FNV_ITER_57(s,h))
#define FNV_ITER_59(s,h) FNV_STEP((s)[59], FNV_ITER_58(s,h))
#define FNV_ITER_60(s,h) FNV_STEP((s)[60], FNV_ITER_59(s,h))
#define FNV_ITER_61(s,h) FNV_STEP((s)[61], FNV_ITER_60(s,h))
#define FNV_ITER_62(s,h) FNV_STEP((s)[62], FNV_ITER_61(s,h))
#define FNV_ITER_63(s,h) FNV_STEP((s)[63], FNV_ITER_62(s,h))

// Compile-time selection for up to 64 chars
#define HASH(s) ((HASH_t)( \
    sizeof(s)-1 == 1  ? FNV_ITER_0(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 2  ? FNV_ITER_1(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 3  ? FNV_ITER_2(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 4  ? FNV_ITER_3(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 5  ? FNV_ITER_4(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 6  ? FNV_ITER_5(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 7  ? FNV_ITER_6(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 8  ? FNV_ITER_7(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 9  ? FNV_ITER_8(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 10 ? FNV_ITER_9(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 11 ? FNV_ITER_10(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 12 ? FNV_ITER_11(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 13 ? FNV_ITER_12(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 14 ? FNV_ITER_13(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 15 ? FNV_ITER_14(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 16 ? FNV_ITER_15(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 17 ? FNV_ITER_16(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 18 ? FNV_ITER_17(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 19 ? FNV_ITER_18(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 20 ? FNV_ITER_19(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 21 ? FNV_ITER_20(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 22 ? FNV_ITER_21(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 23 ? FNV_ITER_22(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 24 ? FNV_ITER_23(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 25 ? FNV_ITER_24(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 26 ? FNV_ITER_25(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 27 ? FNV_ITER_26(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 28 ? FNV_ITER_27(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 29 ? FNV_ITER_28(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 30 ? FNV_ITER_29(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 31 ? FNV_ITER_30(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 32 ? FNV_ITER_31(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 33 ? FNV_ITER_32(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 34 ? FNV_ITER_33(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 35 ? FNV_ITER_34(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 36 ? FNV_ITER_35(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 37 ? FNV_ITER_36(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 38 ? FNV_ITER_37(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 39 ? FNV_ITER_38(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 40 ? FNV_ITER_39(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 41 ? FNV_ITER_40(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 42 ? FNV_ITER_41(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 43 ? FNV_ITER_42(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 44 ? FNV_ITER_43(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 45 ? FNV_ITER_44(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 46 ? FNV_ITER_45(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 47 ? FNV_ITER_46(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 48 ? FNV_ITER_47(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 49 ? FNV_ITER_48(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 50 ? FNV_ITER_49(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 51 ? FNV_ITER_50(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 52 ? FNV_ITER_51(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 53 ? FNV_ITER_52(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 54 ? FNV_ITER_53(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 55 ? FNV_ITER_54(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 56 ? FNV_ITER_55(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 57 ? FNV_ITER_56(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 58 ? FNV_ITER_57(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 59 ? FNV_ITER_58(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 60 ? FNV_ITER_59(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 61 ? FNV_ITER_60(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 62 ? FNV_ITER_61(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 63 ? FNV_ITER_62(s,FNV32_OFFSET) : \
    sizeof(s)-1 == 64 ? FNV_ITER_63(s,FNV32_OFFSET) : FNV32_OFFSET))

// Runtime 32-bit FNV-1a
static unsigned runtime_hash(const char* s) {
    unsigned hash = FNV32_OFFSET;
    while (*s) {
        hash = (hash ^ (unsigned char)(*s++)) * FNV32_PRIME;
    }
    return hash;
}
