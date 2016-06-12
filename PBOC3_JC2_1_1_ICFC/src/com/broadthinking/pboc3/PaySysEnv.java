package com.broadthinking.pboc3;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * PSE/PPSE Applet implement.
 * @author broadthinking
 */
public class PaySysEnv extends Applet implements AppletEvent {
	
	/**
	 * Card life cycle.
	 */
	private static final byte CARD_STATE_INIT	= 0x01;
	private static final byte CARD_STATE_ISSUED	= 0x02;
	private static final byte CARD_STATE_LOCKED	= 0x03;
	
	/**
	 * App Type: PSE or PPSE, determined by instance AID.
	 */
	private static final byte[] ppse_aid 				= new byte[] {0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31};
	private static final byte TYPE_PSE					= 0x01;
	private static final byte TYPE_PPSE					= 0x02;	

	private byte type;
	
	/**
	 * App life cycle.
	 */
	private static final byte APP_STATE_INIT			= 0x01;
	private static final byte APP_STATE_ISSUED			= 0x02;
	
	private byte appState;
	
	/**
	 * FCI data for PSE
	 */
	private static final short DGI_PERSO_9102		= (short)0x9102;
	
	private byte[] fci;
	
	/**
	 * Linear Record File.
	 */
	private static final byte INVALID_RECORD_OBJECT_INDEX	= (byte) 0xFF;	
	private static final byte RECORD_OBJECT_SIZE			= 30;
	
	private Object[] recordObj;
	private short[] recordMap;
	
	/**
	 * Command INS
	 */
	private static final byte CMD_INS_READ_RECORD    	= (byte)0xB2;
	private static final byte CMD_INS_STORE_DATA		= (byte)0xE2;
	
	/**
	 * Temp variable for STORE-DATA P2.
	 * It's not use RAM because Perso is a small quantity of operation.
	 */
	private byte blockNum;
	
	/**
	 * Constructor of PSE/PPSE. create storage and set state machine.
	 */
	private PaySysEnv() {		
		PBOC.maxAppletNum++;
		PBOC.cardState[0x00] = CARD_STATE_INIT;
		
		appState = APP_STATE_INIT;
		recordObj = new Object[RECORD_OBJECT_SIZE];
		recordMap = new short[RECORD_OBJECT_SIZE];					
	}
	
	/**
	 * Install method, called by JCRE when installed.
	 * @param bArray	Install parameters.
	 * @param bOffset	offset of parameters.
	 * @param bLength	length of parameters.
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new PaySysEnv().register(bArray, (short) (bOffset + 1), bArray[bOffset]);				
	}
	
	/**
	 * Process method, called by JCRE when APDU is dispacher.
	 * @param apdu		APDU be dispachered.
	 */
	public void process(APDU apdu) throws ISOException {
		
		byte[] cmdbuf = apdu.getBuffer();		
		
		// command not support when Card locked.
		if (PBOC.cardState[0] == CARD_STATE_LOCKED) {
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		
		// select command.
		if (selectingApplet()) {	
			
			// PPSE should not be selected via contact interface.
			if ((type == TYPE_PPSE)
				&& (APDU.getProtocol() == 0x00)) {
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			}
			
			if (fci != null) {
				short len = (short) fci.length;
				Util.arrayCopyNonAtomic(fci, (short) 0x00, cmdbuf, ISO7816.OFFSET_CDATA, len);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
			}
			
			return;
		}
		
		SecureChannel sc;
		byte ins = cmdbuf[ISO7816.OFFSET_INS];
		short sLen = 0x00;
		
		switch (ins) {
		case CMD_INS_STORE_DATA: {
			//store data should work on secure channel.
			sc = GPSystem.getSecureChannel();
			if (sc.getSecurityLevel() == SecureChannel.NO_SECURITY_LEVEL) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			onStoreData(sc, apdu);
		}
		break;
		case CMD_INS_READ_RECORD:
			sLen = onReadRecord(cmdbuf);
			break;
		default: 
			//scp command dispacher.
			sc = GPSystem.getSecureChannel();
			sLen = sc.processSecurity(apdu);
		}
		
		if (sLen > 0x00) {
			apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, sLen);
		}
	}

	/**
	 * uninstall method, called by JCRE when deleted.
	 */
	public void uninstall() {
		JCSystem.beginTransaction();		
		
		if (appState != APP_STATE_INIT) {
			PBOC.curPersoAppletNum--;
		}
		PBOC.maxAppletNum--;
		
		JCSystem.commitTransaction();	
	}
	
	/**
	 * STORE-DATA Command route. no RAPDU.
	 * @param sc		SecureChannel.
	 * @param apdu		APDU.
	 */
	private void onStoreData(SecureChannel sc, APDU apdu) {
		byte[] cmdbuf = apdu.getBuffer();
		
		//STORE DATA can only support in INIT state.
		if (APP_STATE_INIT != appState) {
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		
		//chainning check.
		if (blockNum != cmdbuf[ISO7816.OFFSET_P2]) {
			blockNum = 0x00;
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		//recv & unwrap APDU.
		apdu.setIncomingAndReceive();

		sc.unwrap(cmdbuf, (short) 0x00, (short) (0x05+(short)(cmdbuf[ISO7816.OFFSET_LC]&0x00FF)));
		
		//data structure: DGI|len|value
		short dgi;
		short sOff = (short) (ISO7816.OFFSET_CDATA+2);
		short sLen;		
		
		JCSystem.beginTransaction();
		
		//dgi always be 2 bytes.
		dgi = Util.getShort(cmdbuf, ISO7816.OFFSET_CDATA);
		
		//length should be XX (len<0x80), or 81XX (0x100>len>0x80).
		sLen = (short) (cmdbuf[sOff++]&0x00FF);
		if (sLen == (short)0x0081) {
			sLen = (short) (cmdbuf[sOff++]&0x00FF);
		}
		
		if ((cmdbuf[ISO7816.OFFSET_CDATA] > 0x00) && (cmdbuf[ISO7816.OFFSET_CDATA] < 0x1F)) {
			//perso record file. DGI should be sfi + record num.
			persoRecContent(dgi, cmdbuf, sOff, sLen);
		} else {
			//perso FCI data. DGI should be 9102.
			persoFCI(dgi, cmdbuf, sOff, sLen);
		}
		
		// last block. update app states.
		if ((byte)(cmdbuf[ISO7816.OFFSET_P1]&0x80) == (byte)0x80) {
			
			PBOC.curPersoAppletNum++;
			if (PBOC.curPersoAppletNum == PBOC.maxAppletNum) {
				PBOC.cardState[0] = CARD_STATE_ISSUED;
			}
			
			appState = APP_STATE_ISSUED;
			blockNum = 0x00;
		} else {
			blockNum++;
		}
		
		JCSystem.commitTransaction();
	}
	
	/**
	 * READ-RECORD Command route. RAPDU is file data.
	 * @param cmdbuf	apdu buffer.
	 * @return length of RAPDU.
	 */
	private short onReadRecord(byte[] cmdbuf) {
		short sLen = 0x00;
		byte index;
		
		//P2 bit3 should be set.
		byte p2 = cmdbuf[ISO7816.OFFSET_P2];
		if ((p2&0x04) != 0x04) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		//find record by sfi and record num.
		p2 >>= 0x03;
		
		index = findRecord(Util.makeShort(p2, cmdbuf[ISO7816.OFFSET_P1]));
		if (index == INVALID_RECORD_OBJECT_INDEX) {
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}
		
		//copy record to apdu buffer.
		byte[] data = (byte[])recordObj[index];
		sLen = (short) data.length;
		
		Util.arrayCopyNonAtomic(data, (short) 0x00, cmdbuf, ISO7816.OFFSET_CDATA, sLen);
		
		return sLen;
	}
	
	/**
	 * perso Record File.
	 * @param dgi		DGI of perso data, should be sfi+num.
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void persoRecContent(short dgi, byte[] cmdbuf, short sOff, short sLen) {
		
		//get free table index.
		byte index = getFreeRecTableIndex();
		
		// not enough record table space
		if (index == INVALID_RECORD_OBJECT_INDEX) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		}
				
		//malloc the record data and set to map.
		byte[] record = new byte[sLen];
		// save record data
		Util.arrayCopyNonAtomic(cmdbuf, sOff, record, (byte) 0x00, sLen);
		
		recordObj[index] = record;
		recordMap[index] = dgi;
		
	}
	
	/**
	 * perso FCI data
	 * @param dgi		DGI of perso data, should be 9102.
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void persoFCI(short dgi, byte[] cmdbuf, short sOff, short sLen) {
		
		//DGI should be 9102
		if(dgi != DGI_PERSO_9102) {
			ISOException.throwIt((short) 0x6A88);
		}
		
		short sTmp;
		short sfciOff;
		short sfciLen;
		
		// Get instance AID to judge the App type.
		sTmp = JCSystem.getAID().getBytes(cmdbuf, (short) (sOff+sLen));
		
		if (Util.arrayCompare(cmdbuf, (short) (sOff+sLen), ppse_aid, (short) 0x00, (short) ppse_aid.length) == 0x00) {
			type = TYPE_PPSE;
		} else {
			type = TYPE_PSE;
		}
		
		// Anaylse TLV and build fci.
		sfciLen = (short) (sLen+sTmp+2);
		if (sfciLen > 0x007F) {
			sfciOff = (short) (sfciLen+3);
		} else {
			sfciOff = (short) (sfciLen+2);
		}
				
		fci = new byte[sfciOff];
		
		sfciOff = 0x00;		
		fci[sfciOff++] = 0x6F;
		if (sfciLen > 0x007F) {
			fci[sfciOff++] = (byte) 0x81;
		}
		
		fci[sfciOff++] = (byte) sfciLen;
		// append AID 84 TLV
		sfciOff = PBOCUtil.appendTLV((short)0x84, cmdbuf, (short) (sOff+sLen), sTmp, fci, sfciOff);
		// append A5 TLV
		Util.arrayCopyNonAtomic(cmdbuf, sOff, fci, sfciOff, sLen);
	}
	
	/**
	 * Find a Free record index in recordObj.
	 * @return index of recordObj.
	 */
	private byte getFreeRecTableIndex() {
		byte index;
		
		for (index = 0x00; index < RECORD_OBJECT_SIZE; index++) {
			if (recordObj[index] == null) {
				return index;
			}
		}
		
		return INVALID_RECORD_OBJECT_INDEX;
	}
	
	/**
	 * Find a record by specific sfi and record num.
	 * @param sDst high byte for sfi, low byte for record num.
	 * @return record index.
	 */
	private byte findRecord(short sDst) {
		byte index;
		
		for (index = 0x00; index < RECORD_OBJECT_SIZE; index++) {
			if (recordMap[index] == sDst) {
				return index;
			}
		}
		
		return INVALID_RECORD_OBJECT_INDEX;
	}
}
