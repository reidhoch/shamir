"""Contains the logarithm and exponentiation tables."""

from typing import Final

LOG_TABLE: Final[list[int]] = [
    0x00,
    0xFF,
    0xC8,
    0x08,
    0x91,
    0x10,
    0xD0,
    0x36,
    0x5A,
    0x3E,
    0xD8,
    0x43,
    0x99,
    0x77,
    0xFE,
    0x18,
    0x23,
    0x20,
    0x07,
    0x70,
    0xA1,
    0x6C,
    0x0C,
    0x7F,
    0x62,
    0x8B,
    0x40,
    0x46,
    0xC7,
    0x4B,
    0xE0,
    0x0E,
    0xEB,
    0x16,
    0xE8,
    0xAD,
    0xCF,
    0xCD,
    0x39,
    0x53,
    0x6A,
    0x27,
    0x35,
    0x93,
    0xD4,
    0x4E,
    0x48,
    0xC3,
    0x2B,
    0x79,
    0x54,
    0x28,
    0x09,
    0x78,
    0x0F,
    0x21,
    0x90,
    0x87,
    0x14,
    0x2A,
    0xA9,
    0x9C,
    0xD6,
    0x74,
    0xB4,
    0x7C,
    0xDE,
    0xED,
    0xB1,
    0x86,
    0x76,
    0xA4,
    0x98,
    0xE2,
    0x96,
    0x8F,
    0x02,
    0x32,
    0x1C,
    0xC1,
    0x33,
    0xEE,
    0xEF,
    0x81,
    0xFD,
    0x30,
    0x5C,
    0x13,
    0x9D,
    0x29,
    0x17,
    0xC4,
    0x11,
    0x44,
    0x8C,
    0x80,
    0xF3,
    0x73,
    0x42,
    0x1E,
    0x1D,
    0xB5,
    0xF0,
    0x12,
    0xD1,
    0x5B,
    0x41,
    0xA2,
    0xD7,
    0x2C,
    0xE9,
    0xD5,
    0x59,
    0xCB,
    0x50,
    0xA8,
    0xDC,
    0xFC,
    0xF2,
    0x56,
    0x72,
    0xA6,
    0x65,
    0x2F,
    0x9F,
    0x9B,
    0x3D,
    0xBA,
    0x7D,
    0xC2,
    0x45,
    0x82,
    0xA7,
    0x57,
    0xB6,
    0xA3,
    0x7A,
    0x75,
    0x4F,
    0xAE,
    0x3F,
    0x37,
    0x6D,
    0x47,
    0x61,
    0xBE,
    0xAB,
    0xD3,
    0x5F,
    0xB0,
    0x58,
    0xAF,
    0xCA,
    0x5E,
    0xFA,
    0x85,
    0xE4,
    0x4D,
    0x8A,
    0x05,
    0xFB,
    0x60,
    0xB7,
    0x7B,
    0xB8,
    0x26,
    0x4A,
    0x67,
    0xC6,
    0x1A,
    0xF8,
    0x69,
    0x25,
    0xB3,
    0xDB,
    0xBD,
    0x66,
    0xDD,
    0xF1,
    0xD2,
    0xDF,
    0x03,
    0x8D,
    0x34,
    0xD9,
    0x92,
    0x0D,
    0x63,
    0x55,
    0xAA,
    0x49,
    0xEC,
    0xBC,
    0x95,
    0x3C,
    0x84,
    0x0B,
    0xF5,
    0xE6,
    0xE7,
    0xE5,
    0xAC,
    0x7E,
    0x6E,
    0xB9,
    0xF9,
    0xDA,
    0x8E,
    0x9A,
    0xC9,
    0x24,
    0xE1,
    0x0A,
    0x15,
    0x6B,
    0x3A,
    0xA0,
    0x51,
    0xF4,
    0xEA,
    0xB2,
    0x97,
    0x9E,
    0x5D,
    0x22,
    0x88,
    0x94,
    0xCE,
    0x19,
    0x01,
    0x71,
    0x4C,
    0xA5,
    0xE3,
    0xC5,
    0x31,
    0xBB,
    0xCC,
    0x1F,
    0x2D,
    0x3B,
    0x52,
    0x6F,
    0xF6,
    0x2E,
    0x89,
    0xF7,
    0xC0,
    0x68,
    0x1B,
    0x64,
    0x04,
    0x06,
    0xBF,
    0x83,
    0x38,
]

EXP_TABLE: Final[list[int]] = [
    0x01,
    0xE5,
    0x4C,
    0xB5,
    0xFB,
    0x9F,
    0xFC,
    0x12,
    0x03,
    0x34,
    0xD4,
    0xC4,
    0x16,
    0xBA,
    0x1F,
    0x36,
    0x05,
    0x5C,
    0x67,
    0x57,
    0x3A,
    0xD5,
    0x21,
    0x5A,
    0x0F,
    0xE4,
    0xA9,
    0xF9,
    0x4E,
    0x64,
    0x63,
    0xEE,
    0x11,
    0x37,
    0xE0,
    0x10,
    0xD2,
    0xAC,
    0xA5,
    0x29,
    0x33,
    0x59,
    0x3B,
    0x30,
    0x6D,
    0xEF,
    0xF4,
    0x7B,
    0x55,
    0xEB,
    0x4D,
    0x50,
    0xB7,
    0x2A,
    0x07,
    0x8D,
    0xFF,
    0x26,
    0xD7,
    0xF0,
    0xC2,
    0x7E,
    0x09,
    0x8C,
    0x1A,
    0x6A,
    0x62,
    0x0B,
    0x5D,
    0x82,
    0x1B,
    0x8F,
    0x2E,
    0xBE,
    0xA6,
    0x1D,
    0xE7,
    0x9D,
    0x2D,
    0x8A,
    0x72,
    0xD9,
    0xF1,
    0x27,
    0x32,
    0xBC,
    0x77,
    0x85,
    0x96,
    0x70,
    0x08,
    0x69,
    0x56,
    0xDF,
    0x99,
    0x94,
    0xA1,
    0x90,
    0x18,
    0xBB,
    0xFA,
    0x7A,
    0xB0,
    0xA7,
    0xF8,
    0xAB,
    0x28,
    0xD6,
    0x15,
    0x8E,
    0xCB,
    0xF2,
    0x13,
    0xE6,
    0x78,
    0x61,
    0x3F,
    0x89,
    0x46,
    0x0D,
    0x35,
    0x31,
    0x88,
    0xA3,
    0x41,
    0x80,
    0xCA,
    0x17,
    0x5F,
    0x53,
    0x83,
    0xFE,
    0xC3,
    0x9B,
    0x45,
    0x39,
    0xE1,
    0xF5,
    0x9E,
    0x19,
    0x5E,
    0xB6,
    0xCF,
    0x4B,
    0x38,
    0x04,
    0xB9,
    0x2B,
    0xE2,
    0xC1,
    0x4A,
    0xDD,
    0x48,
    0x0C,
    0xD0,
    0x7D,
    0x3D,
    0x58,
    0xDE,
    0x7C,
    0xD8,
    0x14,
    0x6B,
    0x87,
    0x47,
    0xE8,
    0x79,
    0x84,
    0x73,
    0x3C,
    0xBD,
    0x92,
    0xC9,
    0x23,
    0x8B,
    0x97,
    0x95,
    0x44,
    0xDC,
    0xAD,
    0x40,
    0x65,
    0x86,
    0xA2,
    0xA4,
    0xCC,
    0x7F,
    0xEC,
    0xC0,
    0xAF,
    0x91,
    0xFD,
    0xF7,
    0x4F,
    0x81,
    0x2F,
    0x5B,
    0xEA,
    0xA8,
    0x1C,
    0x02,
    0xD1,
    0x98,
    0x71,
    0xED,
    0x25,
    0xE3,
    0x24,
    0x06,
    0x68,
    0xB3,
    0x93,
    0x2C,
    0x6F,
    0x3E,
    0x6C,
    0x0A,
    0xB8,
    0xCE,
    0xAE,
    0x74,
    0xB1,
    0x42,
    0xB4,
    0x1E,
    0xD3,
    0x49,
    0xE9,
    0x9C,
    0xC8,
    0xC6,
    0xC7,
    0x22,
    0x6E,
    0xDB,
    0x20,
    0xBF,
    0x43,
    0x51,
    0x52,
    0x66,
    0xB2,
    0x76,
    0x60,
    0xDA,
    0xC5,
    0xF3,
    0xF6,
    0xAA,
    0xCD,
    0x9A,
    0xA0,
    0x75,
    0x54,
    0x0E,
    0x01,
]
