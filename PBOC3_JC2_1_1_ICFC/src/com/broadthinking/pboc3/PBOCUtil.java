package com.broadthinking.pboc3;

import javacard.framework.Util;

/**
 * PBOC Util class.
 * @author broadthinking
 */
public class PBOCUtil {
	
	/**
	 * fail result for find operation.
	 */
	public static final short TAG_NOT_FOUND = -1;
	
	/**
	 * DEC array length.
	 */
	private static final byte DEC_ARRAY_LENGTH 		= (byte)6;
	
	/**
	 * append specific BER-TLV to dest buffer
	 * @param tag			tag to be append.
	 * @param value			value to be append.
	 * @param sValueOff		value's offset.
	 * @param sValueLen		value's length.
	 * @param dest			dest buffer.
	 * @param sDestOff		dest's offset.
	 * @return sDestOff + TLV len.
	 */
	public static short appendTLV(short sTag, byte[] value, short sValueOff, short sValueLen, byte[] dest, short sDestOff) {
		short sOff = sDestOff;
		
		// append tag.
		if ((sTag&0x1F00) == (short) 0x1F00) {
			Util.setShort(dest, sOff, sTag);
			sOff += 2;
		} else {
			dest[sOff++] = (byte) sTag;
		}
		
		// append length.
		if (sValueLen > 0x7F) {
			dest[sOff++] = (byte) 0x81;
		}
		
		dest[sOff++] = (byte) sValueLen;
		
		// append value.
		Util.arrayCopy(value, sValueOff, dest, sOff, sValueLen);
		
		return (short) (sOff+sValueLen);
	}
	
	/**
	 * append specific BER-TLV(L=2) to dest buffer
	 * @param sTag		tag to be append.
	 * @param sValue	value to be append.
	 * @param dest		dest buffer.
	 * @param sDestOff	dest's offset.
	 * @return sDestOff + TLV len.
	 */
	public static short appendTLV(short sTag, short sValue, byte[] dest, short sDestOff) {
		short sOff = sDestOff;
		
		// append tag
		if ((sTag&0x1F00) == (short) 0x1F00) {
			Util.setShort(dest, sOff, sTag);
			sOff += 2;
		} else {
			dest[sOff++] = (byte) sTag;
		}
		
		// append length
		dest[sOff++] = 2;
		
		// append value
		Util.setShort(dest, sOff, sValue);
		sOff += 2;
		
		return sOff;
	}
	
	/**
	 * Calc Value capacity by TL list.
	 * @param list		buffer of TL list.
	 * @param sOff		offset of TL list.
	 * @param sLen		length of TL list.
	 * @return	Value capacity.
	 */
	public static short getValueLenByTLList(byte[] list, short sOff, short sLen) {
		short sTag;
		short sValueLen;
		short sValuesLen = 0;
		
		sLen += sOff;
		for (; sOff < sLen;) {
			sTag = (short) (list[sOff++]&0x00FF);
			if (((short)(sTag&0x001F)) == ((short)0x001F)) {
				sTag <<= 8;
				sTag |= (short) (list[sOff++]&0x00FF);
			}
			
			sValueLen = (short) (list[sOff++]&0x00FF);
			if (sValueLen == (short) 0x81) {
				sValueLen = (short) (list[sOff++]&0x00FF);
			}
			
			sValuesLen += sValueLen;
		}
	
		return sValuesLen;
	}
	
	/**
	 * Get offset of Value capacity by specific tag in TL list.
	 * @param tag			tag to be find.
	 * @param list			buffer of TL list.
	 * @param listOff		offset of TL list.
	 * @param listLen		length of TL list.
	 * @return offset of Value capacity. return TAG_NOT_FOUND if cant find.
	 */
	public static short findValuePosInTLList(short tag, byte[] list, short listOff, short listLen) {
		short sTag;
		short sValueLen;
		short sValueOff;
		
		listLen += listOff;
		sValueOff = 0x00;
		for (; listOff < listLen;) {
			sTag = (short) (list[listOff++]&0x00FF);
			if (((short)(sTag&0x001F)) == ((short)0x001F)) {
				sTag <<= 8;
				sTag |= (short) (list[listOff++]&0x00FF);
			}
			
			if (sTag == tag) {
				return sValueOff;
			}
			
			sValueLen = (short) (list[listOff++]&0x00FF);
			if (sValueLen == (short) 0x81) {
				sValueLen = (short) (list[listOff++]&0x00FF);
			}
			
			sValueOff += sValueLen;
		}
	
		return TAG_NOT_FOUND;
	}
	
	/**
	 * Get offset of value by specific tag in BER-TLV list.
	 * @param tag			tag to be find.
	 * @param tlvList		buffer of tlv list.
	 * @param offset		offset of buffer.
	 * @param length		length of buffer.
	 * @return offset of value, TAG_NOT_FOUND if can't find.
	 */
	public static short findValueOffByTag(short tag, byte[] tlvList, short offset, short length){
		short i = offset;
		length += offset;	
		
		while(i<length){
			//tag
			short tagTemp = (short) (tlvList[i]&0x00FF);
			if((short)(tagTemp&0x001F) == 0x001F){
				i++;
				tagTemp <<= 8;
				tagTemp |= (short) (tlvList[i]&0x00FF);
			}
			i++;
			
			//length
			if(tlvList[i] == (byte) 0x81){
				i++;
			}
			i++;
			
			//value
			if(tag == tagTemp){
				return i;
			}
			
			i += (tlvList[(short)(i-1)]&0x00FF);
		}
		return TAG_NOT_FOUND;
	}

	
	
	/**
	 * judge specify bit is set in flags buffer.
	 * @param flags		buffer of flags.
	 * @param bitOff	specify bit offset.
	 * @return if set return true else false
	 */
	public static boolean isBitSet(byte[] flags, short sOff, short bitOff){
		
		short sByteOff = (short) (bitOff >> 3);
		short sBitOff = (short) (bitOff % 8);
		byte bitValue = (byte) (1 << (short) (7-sBitOff));
		return ((flags[(short) (sOff+sByteOff)]&bitValue) == bitValue);
	}
		
	/**
	 * set specify bit in flags buffer.
	 * @param flags		buffer of flags.
	 * @param bitOff	specify bit offset.
	 */
	public static void setBit(byte[] flags, short sOff, short bitOff){
		short sByteOff = (short) (bitOff >> 3);
		short sBitOff = (short) (bitOff % 8);
		byte bitValue = (byte) (1 << (short) (7-sBitOff));
		flags[(short)(sOff+sByteOff)] |= bitValue;
	}
	
	/**
	 * clear specify bit in flags buffer.
	 * @param flags		buffer of flags.
	 * @param bitOff	specify bit offset.
	 */
	public static void clearBit(byte[] flags, short sOff, short bitOff){
		short sByteOff = (short) (bitOff >> 3);
		short sBitOff = (short) (bitOff % 8);
		byte bitValue = (byte) (1 << (short) (7-sBitOff));
		flags[(short)(sOff+sByteOff)] &= (~bitValue);
	}
	
	/**
	 * Compares an array from the specified source array, beginning at the specified position, with the specified 
	 * position of the destination array fromleft to right.  notice: the compare is unsigned.
	 * @param src			source byte array.
	 * @param srcOff		source byte array offset.
	 * @param dest			dest byte array.
	 * @param destOff		dest byte array offset.
	 * @param length		length of compare data.
	 * @return Returns the ternary result of the comparison : less  than(-1), equal(0) or greater than(1).
	 */
	public static final byte arrayCompare(byte src[], short srcOff, byte dest[], short destOff, short length) {
    	short sf, st;
    	for(short i=0; i<length; i++) {
    		sf = (short)(src[(short)(i+srcOff)]&0x00FF);
    		st = (short)(dest[(short)(i+destOff)]&0x00FF);
    		if(sf == st) {
    			continue;
    		} else if(sf > st){
    			return 1;
    		} else{
    			return -1;
    		}
    	}
    	return 0;
    }
	
	/**
	 * Trans hexByte to DecByte, exp 0x10 to 10.
	 * @param hexByte	Hex byte.
	 * @return Dec byte.
	 */
	private static byte toDecByte(byte hexByte) {
		
		byte hi, lo;
		
		hi = (byte)((hexByte >> 4) & 0xF);
		lo = (byte)(hexByte & 0xF);
		
		return (byte)(hi * 10 + lo);
	}
	
	/**
	 * Trans decByte to Hex Byte, exp 10 to 0x10
	 * @param decByte	Dec byte.
	 * @return	Hex byte.
	 */
	private static byte toHexByte(short decByte) {
		
		byte hi, lo;
		
		lo = (byte)(decByte % 10);
		hi = (byte)(decByte / 10);
		
		return (byte)((hi << 4) | lo);
	}
	
	/**
	 * judge is all zero in byte array.
	 * @param data		byte array.
	 * @param sOff		offset of byte array.
	 * @param sLen		length of byte array.
	 * @return			
	 */
	public static boolean isAllZero(byte[] data, short sOff, short sLen) {		
		while ((sLen--) > 0) {		
			if (data[sOff++] != 0x00) {
				return false;
			}
		}
		
		return true;
	}
	
	/**
	 * array unsigned byte hex add with carry.
	 * exp, {0x00,0xFF,0xFF,0xFF} + {0x00,0x00,0x00,0x01} = {0x01,0x00,0x00,0x00}.
	 * @param from		src byte array.
	 * @param fOff		offset of src byte array.
	 * @param to		dst byte array.
	 * @param tOff		offset of dst byte array.
	 * @param l			length of add operation.
	 * @param out		out byte array.
	 * @param oOff		offset of out byte array.
	 * @return false for overflow/true for not overflow
	 */
	public static boolean arrayHexAdd(byte[] from, short fOff, byte[] to, short tOff, byte[] out, short oOff, short length){
		short sValue;
		byte c;
		c = (byte)0;		
		for(short i=(short)(length-1); i>=0; i--) {			
			sValue = (short)((short)(from[(short)(fOff+i)]&0x00FF)+ (short)(to[(short)(tOff + i)]&0x00FF) + c);
						
			if(sValue > (short)0x00FF) {
				c = (byte)1;
			}else{
				c = (byte)0;
			}
			out[(short)(oOff + i)] = (byte)sValue;
		}
		
		return c==0;
	}
	
	/**
	 * array unsigned byte dec add with carry. length should always be 6
	 * exp, {0x00,0x00,0x09,0x99,0x99} + {0x00,0x00,0x00,0x00,0x01} = {0x00,0x00,0x10,0x00,0x00}
	 * @param from		src byte array.
	 * @param fOff		offset of src byte array.
	 * @param to		dst byte array.
	 * @param tOff		offset of dst byte array.
	 * @param out		out byte array.
	 * @param oOff		offset of out byte array.
	 */
	public static void arrayDecAdd(byte[] augend, short augOff, byte[] addend, short addOff, byte[] out, short oOff) {
		
		short sf, st;
		byte c;
			
		c = (byte)0;
		
		for(byte i = (byte)(DEC_ARRAY_LENGTH - 1); i >= 0; i--) {
			
			sf = toDecByte(augend[(short)(augOff + i)]);
			
			st = (byte)(toDecByte(addend[(short)(addOff + i)]) + c);
			
			c = (byte)0;
			
			st += sf;
			
			if(st > 99) {
				
				st -= 100;
				c = (byte)1;
			}
			
			out[(short)(oOff + i)] = toHexByte(st);
		}
	}
	
	/**
	 * array unsigned byte dec sub with carry. length should always be 6
	 * exp, {0x00,0x00,0x10,0x00,0x00} - {0x00,0x00,0x09,0x99,0x99} = {0x00,0x00,0x00,0x00,0x01}
	 * @param minuend			minuend buffer.
	 * @param mOff				offset of minuend buffer.
	 * @param subtrahend		subtrahend buffer.
	 * @param sOff				offset of subtrahend buffer.
	 * @param out				out buffer.
	 * @param oOff				offset of out buffer.
	 */
	public static void arrayDecSub(byte[] minuend, short mOff, byte[] subtrahend, short sOff, byte[] out, short oOff) {
		short sMinuend, sSubtrahend;
		byte c = (byte) 0;
		
		for (byte i = (byte)(DEC_ARRAY_LENGTH - 1); i >= 0; i--) {
			sMinuend = toDecByte(minuend[(short) (mOff+i)]);
			sSubtrahend = (short)(toDecByte(subtrahend[(short) (sOff+i)]) + c);
			
			c = (byte) 0;
			
			if (sMinuend < sSubtrahend) {
				c = (byte) 1;
				sMinuend += 100;
			}
			
			sMinuend -= sSubtrahend;
			
			out[(short)(oOff + i)] = toHexByte(sMinuend);
		}
	}
	
	
	/**
	 * array unsigned byte dec mul with carry. length should always be 6
	 * @param data1			data buffer.
	 * @param sData1Off		offset of data buffer.
	 * @param data2			data buffer.
	 * @param sData2Off		offset of data buffer.
	 * @param out			out buffer.
	 * @param sOutOff		offset of out buffer.
	 * @param gene			The decimal point offset.
	 */
	public static void arrayDecMul(byte[] data1, short sData1Off, byte[] data2, short sData2Off, byte[] out, short sOutOff, byte gene) {		
		byte i;
		byte j;
		short u16Sum;
		short u16Mul;
		short u16Carry;
		
		u16Carry = 0x00;

		inversion(data1, sData1Off, DEC_ARRAY_LENGTH);
		inversion(data2, sData2Off, DEC_ARRAY_LENGTH);

		Util.arrayFillNonAtomic(out, sOutOff, (short) 11, (byte) 0x00);

	    for(i=0;i<11;i++) {
			u16Sum = u16Carry;
			u16Carry = 0;
			for(j=0; j<6; j++) {
	            if(((short)(i-j)>=0)&&((short)(i-j)<6)) {
					u16Mul = toDecByte(data1[(short) (sData1Off+i-j)]);
					u16Mul *= toDecByte(data2[(short) (sData2Off+j)]);
					u16Sum += u16Mul;
				}
	        }

			u16Carry = (short) (u16Sum /100);
			out[(short) (sOutOff+i)] = toHexByte((byte) (u16Sum % 100));
		}

		if(u16Carry > 0) 
		{
			out[(short) (sOutOff+i)] = toHexByte(u16Carry);
		}
		
		Util.arrayCopyNonAtomic(out, (short) (sOutOff+gene/2), out, sOutOff, DEC_ARRAY_LENGTH);
		
		inversion(data1, sData1Off, DEC_ARRAY_LENGTH);
		inversion(data2, sData2Off, DEC_ARRAY_LENGTH);
		inversion(out, sOutOff, DEC_ARRAY_LENGTH);
	}
	
	/**
	 * array unsigned byte xor operation.
	 * @param dest			dest buffer.
	 * @param destOff		offset of dest buffer.
	 * @param src			src buffer.
	 * @param srcOff		offset of src buffer.
	 * @param Len			length of data.
	 */
	public static void arrayXor(byte[] dest, short destOff, byte[] src, short srcOff, short Len) {
		for (short i=0; i<Len; i++) {
			dest[(short)(i+destOff)] ^= src[(short)(i+srcOff)];
		}
	}
	
	/**
	 * inversion of byte array.
	 * exp, {0x12,0x34,0x56,0x78} to {0x78,0x56,0x34,0x12}
	 * @param data		data buffer to be inversion.
	 * @param sOff		offset of data buffer.
	 * @param sLen		length of data buffer.
	 */
	private static void inversion(byte[] data, short sOff, short sLen) {
		short i;
		byte byTemp;
		short sTimes;
		
		sTimes = (short) (sLen/2);
		
		for (i=0x00; i<sTimes; i++) {
			byTemp = data[(short) (i+sOff)];
			data[(short) (i+sOff)] = data[(short) (sLen-i-1+sOff)];
			data[(short) (sLen-i-1+sOff)] = byTemp;
		}
	}
}
