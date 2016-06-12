package com.broadthinking.pboc3.service;

import javacard.framework.Shareable;

public interface IPBOCService extends Shareable {

	/**
	 * 供STK访问
	 * @param inCommand	receive APDU Byte
	 * @param outCommand	send APDU Byte
	 * @return 传出数据的长度
	 */
	public short transmitAPDU(byte[] inCommand, byte [] outCommand);
}
