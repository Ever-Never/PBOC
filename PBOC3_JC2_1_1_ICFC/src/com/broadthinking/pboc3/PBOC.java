package com.broadthinking.pboc3;

import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateCrtKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * PBOC Applet implement.
 * @author broadthinking
 *
 */
public class PBOC extends Applet implements AppletEvent {
	/**
	 * app version 1.0.0
	 */
	private static final byte[] app_version = new byte[] {0x01, 0x00, 0x00};
	/**
	 * app name CFCPBOC
	 */
	private static final byte[] app_name	= new byte[] {0x43, 0x46, 0x43, 0x50, 0x42, 0x4F, 0x43};
	
	private byte[] backRecord;
	
	private static final boolean FUNCTION_FOR_TIANYU	= true;//true 兼容天喻
	
	private short persoDGI;
	private short persoDGIOff;
	/**
	 * app state
	 */
	private byte appState;	
	/**
	 * enternal auth failed counter
	 */
	private short externalAuthFailedCntr;
	/**
	 * mac failed counter
	 */
	private short macFailedCntr;
	
	/**
	 * media data
	 */
	private byte[] cardDataBuf;
	/**
	 * param data, des key,sfi,offset,value
	 */
	private byte[] paramBuf;
	/**
	 * trade terminal data offset in CDOL1/CDOL2 Value
	 */
	private byte[] terDataInCDOLVOff;
	/**
	 * QPBOC Signature DGI
	 */
	private short sQPBOCSigDGI;
	/**
	 * QPBOC Signature's offset in DGI 
	 */
	private short sQPBOCSigOff;
	/**
	 * QPBOC 9F5D DGI
	 */
	private short sQPBOC9F5DDGI;
	/**
	 * QPBOC 9F5D's offset in DGI
	 */
	private short sQPBOC9F5DOff;
	/**
	 * QPBOC Last Record DGI
	 */
	private short sQPBOCLastRecDGI;
	/**
	 * QPBOC ARQC/AAC GPO RSP ATC Value Offset
	 */
	private short sQPBOCARQCAACRspATCOff;
	/**
	 * QPBOC ARQC/AAC GPO RSP ISSUE APP Data Value Offset
	 */
	private short sQPBOCARQCAACRspIssueAPPOff;	
	/**
	 * QPBOC ARQC/AAC GPO RSP App AC Value Offset
	 */
	private short sQPBOCARQCAACRspACOff;
	/**
	 * QPBOC ARQC/AAC GPO RSP Card Trade Attr Offset
	 */
	private short sQPBOCARQCAACRspCardAttrOff;
	/**
	 * QPBOC ARQC/AAC GPO RSP Available Offline trade Money
	 */
	private short sQPBOCARQCAACRspAvailMoneyOff;
	/**
	 * QPBOC TC GPO RSP ATC Value Offset
	 */
	private short sQPBOCTCRspATCOff;
	/**
	 * QPBOC TC GPO RSP App AC Value Offset
	 */
	private short sQPBOCTCRspACOff;
	/**
	 * QPBOC TC GPO RSP ISSUE APP Data Value Offset
	 */
	private short sQPBOCTCRspIssueAppOff;
	/**
	 * QPBOC TC GPO RSP ICC Signature Value Offset
	 */
	private short sQPBOCTCRspICCSIGOff;
	/**
	 * QPBOC TC GPO RSP Card Trade Attr Offset
	 */
	private short sQPBOCTCRspCardAttrOff;
	/**
	 * QPBOC TC GPO RSP Available Offline trade Money, 0x01 byte
	 */
	private short sQPBOCTCRspAvailMoneyOff;
	/**
	 * 0xDF61's offset in FCI, 1 byte
	 */
	private short sExtAppIndicateOff;	
	/**
	 * QPBOC Issue application data length
	 */
	private short sQPBOCIssueAppDataLen;
	/**
	 * EC Terminal support indicate offset in QPBOC PDOL Value
	 */
	private short sQPDOLECTerSupportIndicateOff;
	/**
	 * Terminal Trade Attribute Offset in QPBOC PDOL Value
	 */
	private short sQPDOLVTerminalTradeAttrOff;
	/**
	 * trade coin code Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTradeCoinCodeOff;
	/**
	 * trade auth money Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTradeAuthMoneyOff;
	/**
	 * trade random Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTerminalTradeRandomOff;
	/**
	 * trade other money Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTradeOtherMoneyOff;
	/**
	 * terminal state code Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTerminalStateCodeOff;
	/**
	 * terminal result Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTerminalResultOff;
	/**
	 * trade date Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTradeDateOff;
	/**
	 * trade type Offset in QPBOC PDOL Value
	 */
	private short sQPDOLTradeTypeOff;
	/**
	 * extend application capp indicate in PDOL Value offset
	 */
	private short sQPDOLCAPPIndicateOff;
	/**
	 * EC Terminal support indicate offset in PDOL Value
	 */
	private short sPPDOLECTerSupportIndicateOff;
	/**
	 * trade coin code Offset in PBOC PDOL Value
	 */
	private short sPPDOLTradeCoinCodeOff;
	/**
	 * trade auth money Offset in QPBOC PDOL Value
	 */
	private short sPPDOLTradeAuthMoneyOff;
	
	/**
	 * log format
	 */
	private byte[] logFormat;
	/**
	 * charge log format
	 */
	private byte[] chargelogFormat;
	/**
	 * trade log file
	 */
	private byte[] tradeLogFile;
	/**
	 * charge log file
	 */
	private byte[] chargeLogFile;
	
	//GAC
	/**
	 * first generate ac command log template
	 */
	private short[] logTemplate_1;
	/**
	 * second generate ac command log template
	 */
	private short[] logTemplate_2;
	/**
	 * qpboc first generate ac log template
	 */
	private short[] logTemplate_3;
	/**
	 * qpboc second generate ac log template
	 */
	private short[] logTemplate_4;
	/**
	 * qpboc log template
	 */
	private short[] logTemplate_5;
	
	/**
	 * extend application files object array
	 */
	private Object[] extAppFiles;
	/**
	 * extend application log file
	 */
	private byte[] extendlogFile;
	/**
	 * pre-auth trade context array, item(1 byte sfi + 2 byte ID + 6 byte pre-authorization money = 9 byte) * item number
	 */
	private byte[] extendPreAuthContext;
	/**
	 * update capp data cache command file cache buffer
	 */
	private byte[] extendFileCache;
	/**
	 * current extend application trade cache length
	 */
	private short[] extendFileCacheCurLen;
	/**
	 * trade session buffer
	 */
	private byte[] abyPBOCTradeSession;	
	
	/**
	 * Const-Data by Store-data
	 */
	/*Select FCI*/
	/**
	 * select FCI of contact interface
	 */
	private byte[] contactfci;	
	/**
	 * select FCI of contactless interface
	 */
	private byte[] contactlessfci;
	
	/*GPO Response*/
	//qPBOC GPO Response online& refuse template (need feed ATC\AC\9F10\9F5D)
	private byte[] qpbocARQCACCGPORsp;
	//qPBOC & comprehensive application GPO Response offline template (need feed ATC\AC,optional FDDA\\9F5D)
	private byte[] qpbocTCGPORsp;
	//PBOC GPO Response
	private byte[] pbocGPO;
	//electronic cash GPO Response
	private byte[] ecGPO;
	//qpboc GPO Response
	private byte[] qpbocGPO;	
	
	/**
	 * CDOL1 TL List
	 */
	private byte[] cdol1;
	/**
	 * CDOL2 TL List
	 */
	private byte[] cdol2;
	/**
	 * CDOL1 Value List ram buffer
	 */
	private byte[] cdol1Value;
	/**
	 * CDOL2 Value List ram buffer
	 */
	private byte[] cdol2Value;
	/**
	 * PBOC PDOL TL List
	 */
	private byte[] pbocpdol;
	/**
	 * QPBOC PDOL TL List
	 */
	private byte[] qpbocpdol;
	/**
	 * PDOL Value List ram buffer
	 */
	private byte[] pdolValue;	
	/**
	 * PBOC Issue Application data
	 */
	private byte[] pbocIssueAppData;
	
	//DDA signature template (need feed ddolValue\ATC)
	private byte[] ddaTemplate;	
	
	/**
	 * static condition 
	 */
	// Card Additional Processes 9F68 conditions
	/**
	 * card support ec check
	 */
	private boolean isCPPSupportECCheck;
	/**
	 * card support ec and ctta check
	 */
	private boolean isCPPSupportECAndCTTACheck;
	/**
	 * card support ec or ctta check
	 */
	private boolean isCPPSupportECOrCTTACheck;
	/**
	 * card support check new card
	 */
	private boolean isCPPSupportNewCardCheck;
	/**
	 * card support check pin retry overflow 
	 */
	private boolean isCPPSupportPINCheck;
	/**
	 * card allow Offline trade coin mismatch
	 */
	private boolean isCPPAllowCoinNotMatchOffline;
	/**
	 * card priority select contact PBOC online trade
	 */
	private boolean isCPPFstContactPBOCOnline;
	/**
	 * card return 9F5D
	 */
	private boolean isCPPReturnAvailableMoney;
	/**
	 * card support previously payment
	 */
	private boolean isCPPSupportPrePay;
	/**
	 * card not allow trade coin not match
	 */
	private boolean isCPPNotAllowCoinNotMatchTrade;
	/**
	 * if new card and terminal only support offline then refuse trade
	 */
	private boolean isCPPNewCardOnlySupportOffline;
	/**
	 * QPBOC trade support trade log
	 */
	private boolean isCPPQPBOCSupportTradeLog;
	/**
	 * match coin trade support online PIN
	 */
	private boolean isCPPMatchCoinTradeSupportPIN;
	/**
	 * not match coin trade support online PIN
	 */
	private boolean isCPPNotMatchCoinTradeSupportPIN;
	/**
	 * not match coin trade request CVM
	 */
	private boolean isCPPNotMatchCoinTradeReqCVM;
	/**
	 * card support signature
	 */
	private boolean isCPPSupportSign;
	
	//runtime flags	
	private boolean[] curTradeConditions;
	
	private boolean bCTTAULNotExist;
	private boolean bIsQPBOCSupportDDA;
	private boolean bIsPBOC3;
	// current trade Variables		
	private byte[] abyCurTradeCardData;	
	
	/**
	 * session key buffer
	 */
	private byte[] sessionKey;
	/**
	 * get response data length
	 */
	private short getResponseLen;
	/**
	 * triple des key
	 */
	private DESKey tripleDesKey;
	/**
	 * DES ECB Encrypt
	 */
	private Cipher cipherECBEncrypt;
	/**
	 * DES ECB Decrypt
	 */
	private Cipher cipherECBDecrypt;
	/**
	 * cal mac/ac
	 */
	private Signature signMac;	
	/**
	 * SHA-1 message digest
	 */
	private MessageDigest msgDigest;
	/**
	 * RSA CRT Key
	 */
	private RSAPrivateCrtKey priCRTKey;
	/**
	 * RSA signature
	 */
	private Cipher cipherRSA;
	/**
	 * random
	 */
	private RandomData random;	
	/**
	 * QPBOC Issue application data
	 */
	private static byte[] qpbocIssueAppData = new byte[32];	
	/**
	 * card life cycle.
	 */
	private static final byte CARD_STATE_INIT	= 0x01;
	private static final byte CARD_STATE_ISSUED	= 0x02;
	private static final byte CARD_STATE_LOCKED	= 0x03;	
	/**
	 * card state
	 */
	public static byte[] cardState = new byte[] {CARD_STATE_INIT};
	/**
	 * current PBOC/PSE/PPSE applet instance number
	 */
	public static byte maxAppletNum = 0x00;
	/**
	 * current finish perso instance number
	 */
	public static byte curPersoAppletNum = 0x00;
	
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * extend application file cache buffer size
	 */
	private static final short EXTEND_FILE_CACHE_BUF_SIZE	= 0x200;
	/**
	 * extend application last trade atc and ac, 10 byte
	 */
	private static final short CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO			= 0x00;
	/**
	 * 0x9F69, 8 byte, 卡片认证相关数据
	 */
	private static final short CARD_DATA_OFF_CARD_AUTH_DATA					= (short) (CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO+0x0A);
	/**
	 * 0xDF63, 电子现金分段扣费已抵扣额, 6 byte
	 */
	private static final short CARD_DATA_OFF_SP_DEDUCTION_MONEY				= (short) (CARD_DATA_OFF_CARD_AUTH_DATA+0x08);
	/**
	 * 0x9F5D, 6 byte, 可用脱机消费金额
	 */
	private static final short CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY		= (short) (CARD_DATA_OFF_SP_DEDUCTION_MONEY+0x06);
	/**
	 * 0x9F79, 6 byte, 电子现金余额
	 */
	private static final short CARD_DATA_OFF_EC_BALANCE						= (short) (CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY+0x06);
	/**
	 * 0xDF79, 6 byte, 第二币种电子现金余额
	 */
	private static final short CARD_DATA_OFF_EC_SECOND_BALANCE				= (short) (CARD_DATA_OFF_EC_BALANCE+0x06);
	/**
	 * 累计脱机交易金额, 内部计数器, CTTA
	 */
	private static final short CARD_DATA_OFF_TOTAL_OFFILINE_MONEY			= (short)(CARD_DATA_OFF_EC_SECOND_BALANCE+0x06);
	/**
	 * 0x9F13, 2 byte, PreOnlineATC上次联机交易计数器
	 */
	private static final short CARD_DATA_OFF_PREONLINE_ATC					= (short) (CARD_DATA_OFF_TOTAL_OFFILINE_MONEY+0x06);
	/**
	 * 连续脱机交易计数器(国际-货币), 内部计数器
	 */
	private static final short CARD_DATA_OFF_INTERCOINOFFLINE_ATC			= (short) (CARD_DATA_OFF_PREONLINE_ATC+0x02);	
	/**
	 * 连续脱机交易计数器(国际-国家), 内部计数器
	 */
	private static final short CARD_DATA_OFF_INTERSTATEOFFLINE_ATC			= (short) (CARD_DATA_OFF_INTERCOINOFFLINE_ATC+0x01);	
	/**
	 * 累计脱机交易金额(双货币), 内部计数器
	 */
	private static final short CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY		= (short) (CARD_DATA_OFF_INTERSTATEOFFLINE_ATC+0x01);
	/**
	 * 上次交易指示器, 内部指示器
	 * 上次交易发卡行认证失败指示器
	 */
	private static final short CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED	= (short) (CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY+0x06);	
	/**
	 * 上次交易指示器, 内部指示器
	 * 上次交易发卡行脚本命令数
	 */
	private static final short CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR		= (short) (CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED+0x01);	
	/**
	 * 上次交易指示器, 内部指示器
	 * 上次交易发卡行脚本失败指示器
	 */
	private static final short CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED = (short) (CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR+0x01);
	/**
	 * 上次交易指示器, 内部指示器
	 * 上次交易联机授权指示位
	 */
	private static final short CARD_DATA_OFF_LAST_TRADE_ONLINE_AUTH 		= (short) (CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED+0x01);	
	/**
	 * 上次交易指示器, 内部指示器
	 * 静态数据认证（SDA）失败指示位，标明当上次交易拒绝时 SDA 是否失败
	 */
	private static final short CARD_DATA_OFF_LAST_TRADE_REFUSE_SDA_FAILED	= (short) (CARD_DATA_OFF_LAST_TRADE_ONLINE_AUTH+0x01);	
	/**
	 * 上次交易指示器, 内部指示器
	 * 静态数据认证（DDA）失败指示位，标明当上次交易拒绝时 DDA 是否失败
	 */
	private static final short CARD_DATA_OFF_LAST_TRADE_REFUSE_DDA_FAILED	= (short) (CARD_DATA_OFF_LAST_TRADE_REFUSE_SDA_FAILED+0x01);
	/**
	 * 0x9F6C, 2 byte, 卡片交易属性
	 */
	private static final short CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE			= (short)(CARD_DATA_OFF_LAST_TRADE_REFUSE_DDA_FAILED+0x01);
	/**
	 * 0x9F36, 2 byte, ATC交易计数器
	 */
	private static final short CARD_DATA_OFF_ATC							= (short)(CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE+0x02);
	/**
	 * 0x9F51, 2 byte, 应用货币代码
	 */
	private static final short CARD_DATA_OFF_APPCOINCODE					= (short) (CARD_DATA_OFF_ATC+0x02);
	/**
	 * 0x9F52, 2 byte, ADA 应用缺省行为
	 */
	private static final short CARD_DATA_OFF_ADA							= (short) (CARD_DATA_OFF_APPCOINCODE+0x02);	
	/**
	 * 0x9F54, 6 byte, 累计脱机交易金额限制, CTTAL
	 */
	private static final short CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT			= (short) (CARD_DATA_OFF_ADA+0x02);	
	/**
	 * 0x9F56, 1 byte, 发卡行认证指示位
	 */
	private static final short CARD_DATA_OFF_ISSUE_AUTH_INDICATE			= (short) (CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT+0x06);	
	/**
	 * 0x9F57, 2 byte, 发卡行国家代码
	 */
	private static final short CARD_DATA_OFF_ISSUE_STATE_CODE				= (short) (CARD_DATA_OFF_ISSUE_AUTH_INDICATE+0x01);	
	/**
	 * 0x9F53, 1 byte, 连续脱机交易限制数(国际-货币)
	 */
	private static final short CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT		= (short) (CARD_DATA_OFF_ISSUE_STATE_CODE+0x02);	
	/**
	 * 0x9F58, 1 byte, 连续脱机交易下限
	 */
	private static final short CARD_DATA_OFF_OFFLINE_CARD_LOWLIMIT			= (short) (CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT+0x01);	
	/**
	 * 0x9F59, 1 byte, 连续脱机交易上限
	 */
	private static final short CARD_DATA_OFF_OFFLINE_CARD_UPLIMIT			= (short) (CARD_DATA_OFF_OFFLINE_CARD_LOWLIMIT+0x01);	
	/**
	 * 0x9F72, 1 byte, 连续脱机交易限制数(国际-国家)
	 */
	private static final short CARD_DATA_OFF_STATE_OFFLINE_CARD_LIMIT		= (short) (CARD_DATA_OFF_OFFLINE_CARD_UPLIMIT+0x01);	
	/**
	 * 0x9F5C, 6 byte, 累计脱机交易金额上限
	 */
	private static final short CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT		= (short) (CARD_DATA_OFF_STATE_OFFLINE_CARD_LIMIT+0x01);
	/**
	 * 0x9F63, 16 byte,  产品标识信息
	 */
	private static final short CARD_DATA_OFF_PRODUCET_ID_INFO				= (short) (CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT+0x06);
	/**
	 * 0x9F68, 4 byte, 卡片附加处理
	 */
	private static final short CARD_DATA_OFF_CARD_PLUS_PROCESS				= (short) (CARD_DATA_OFF_PRODUCET_ID_INFO+0x10);
	/**
	 * 0x9F6B, 6 byte, 卡片CVM限额
	 */
	private static final short CARD_DATA_OFF_CARD_CVM_LIMIT					= (short) (CARD_DATA_OFF_CARD_PLUS_PROCESS+0x04);	
	/**
	 * 0x9F6D, 6 byte, 电子现金重置阈值
	 */
	private static final short CARD_DATA_OFF_EC_RESET_THRESHOLD				= (short) (CARD_DATA_OFF_CARD_CVM_LIMIT+0x06);	
	/**
	 * 0x9F73, 4 byte, 货币转换因子
	 */
	private static final short CARD_DATA_OFF_COIN_CONVERT_GENE				= (short) (CARD_DATA_OFF_EC_RESET_THRESHOLD+0x06);	
	/**
	 * 0x9F75, 6 byte, 累计脱机交易金额限制数(双货币)
	 */
	private static final short CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT	= (short) (CARD_DATA_OFF_COIN_CONVERT_GENE+0x04);	
	/**
	 * 0x9F76, 2 byte, 第二应用货币代码
	 */
	private static final short CARD_DATA_OFF_SECOND_APP_COIN_CODE			= (short) (CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT+0x06);	
	/**
	 * 0x9F77, 6 byte, 电子现金余额上限
	 */
	private static final short CARD_DATA_OFF_EC_BALANCE_UPLIMIT				= (short) (CARD_DATA_OFF_SECOND_APP_COIN_CODE+0x02);	
	/**
	 * 0x9F78, 6 byte, 电子现金单笔交易限额
	 */
	private static final short CARD_DATA_OFF_SINGLE_CARD_LIMIT				= (short) (CARD_DATA_OFF_EC_BALANCE_UPLIMIT+0x06);
	/**
	 * 0xDF62, 电子现金分段扣费抵扣限额, 6 byte
	 */
	private static final short CARD_DATA_OFF_SP_DEDUCTION_LIMIT				= (short) (CARD_DATA_OFF_SINGLE_CARD_LIMIT+0x06);
	/**
	 * 0x57, 二磁道等价数据
	 */
	private static final short CARD_DATA_OFF_2ND_TRACK_DATA					= (short) (CARD_DATA_OFF_SP_DEDUCTION_LIMIT+0x06);
	/**
	 * 持卡人姓名
	 */
	private static final short CARD_DATA_OFF_CARD_HOLDER_NAME				= (short) (CARD_DATA_OFF_2ND_TRACK_DATA+20);	
	/**
	 * 应用PAN序列号
	 */
	private static final short CARD_DATA_OFF_PAN							= (short) (CARD_DATA_OFF_CARD_HOLDER_NAME+27);
	/**
	 * 0xDF71, 2 byte, 第二币种电子现金应用货币代码
	 */
	private static final short CARD_DATA_OFF_EC_SECOND_APP_COIN_CODE		= (short) (CARD_DATA_OFF_PAN+0x01);
	/**
	 * 0xDF72, 6 byte, 第二币种卡片 CVM 限额
	 */
	private static final short CARD_DATA_OFF_EC_SECOND_CVM_LIMIT			= (short)(CARD_DATA_OFF_EC_SECOND_APP_COIN_CODE+0x02);
	/**
	 * 0xDF76, 6 byte, 第二币种电子现金重置阈值
	 */
	private static final short CARD_DATA_OFF_EC_SECOND_RESET_THRESHOLD		= (short)(CARD_DATA_OFF_EC_SECOND_CVM_LIMIT+0x06);
	/**
	 * 0xDF77, 6 byte, 第二币种电子现金余额上限
	 */
	private static final short CARD_DATA_OFF_EC_SECOND_BALANCE_LIMIE		= (short)(CARD_DATA_OFF_EC_SECOND_RESET_THRESHOLD+0x06);
	/**
	 * 0xDF78, 6 byte, 第二币种电子现金单笔交易限额
	 */
	private static final short CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT	= (short)(CARD_DATA_OFF_EC_SECOND_BALANCE_LIMIE+0x06);
	
	private static final short CARD_DATA_BUF_SIZE							= (short)(CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT+0x06);
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////		
	
	// PBOC Param
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * DDOL Value Len
	 */
	private static final short PBOC_PARAM_OFF_DDOLVALUE_LEN					= 0x00;
	/**
	 * PBOC PDOL Value Len
	 */
	private static final short PBOC_PARAM_OFF_PBOCPDOLVALUE_LEN				= (short)(PBOC_PARAM_OFF_DDOLVALUE_LEN+0x01);
	/**
	 * QPBOC PDOL Value Len
	 */
	private static final short PBOC_PARAM_OFF_QPBOCPDOLVALUE_LEN			= (short)(PBOC_PARAM_OFF_PBOCPDOLVALUE_LEN+0x01);
	/**
	 * QPBOC AIP, 2 byte
	 */
	private static final short PBOC_PARAM_OFF_QPBOC_AIP						= (short)(PBOC_PARAM_OFF_QPBOCPDOLVALUE_LEN+0x01);
	/**
	 * APP Key, 0x10 byte
	 */
	private static final short PBOC_PARAM_OFF_APP_KEY						= (short)(PBOC_PARAM_OFF_QPBOC_AIP+0x02);	
	/**
	 * MAC Key, 0x10 byte
	 */
	private static final short PBOC_PARAM_OFF_MAC_KEY						= (short)(PBOC_PARAM_OFF_APP_KEY+0x10);	
	/**
	 * DEK Key, 0x10 byte
	 */
	private static final short PBOC_PARAM_OFF_DEK_KEY						= (short)(PBOC_PARAM_OFF_MAC_KEY+0x10);
	/**
	 * PIN left try Count, 0x01 byte
	 */
	private static final short PBOC_PARAM_OFF_PIN_LEFT_CNTR					= (short)(PBOC_PARAM_OFF_DEK_KEY+0x10);	
	/**
	 * PIN Max try Count, 0x01 byte 
	 */
	private static final short PBOC_PARAM_OFF_PIN_MAX_CNTR					= (short)(PBOC_PARAM_OFF_PIN_LEFT_CNTR+0x01);	
	/**
	 * PIN Value, 0x06 byte
	 */
	private static final short PBOC_PARAM_OFF_PIN_VALUE						= (short)(PBOC_PARAM_OFF_PIN_MAX_CNTR+0x01);
																
	private static final short PBOC_PARAM_BUF_SIZE							= (short)(PBOC_PARAM_OFF_PIN_VALUE+0x06);
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	private static final short INVALID_VALUE	= (short) 0xFFFF;
		
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	/**
	 * trade coin code offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TRADE_COIN_CODE			= 0x00;
	/**
	 * trade auth money offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY			= (short)(CDOLV_OFF_CDOL1_TRADE_COIN_CODE+0x01);
	/**
	 * random data offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TERMINAL_TRADE_RANDOM	= (short)(CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY+0x01);
	/**
	 * trade other money offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TRADE_OTHER_MONEY		= (short)(CDOLV_OFF_CDOL1_TERMINAL_TRADE_RANDOM+0x01);
	/**
	 * trade state code offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TERMINAL_STATE_CODE		= (short)(CDOLV_OFF_CDOL1_TRADE_OTHER_MONEY+0x01);
	/**
	 * tvr offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TVR						= (short)(CDOLV_OFF_CDOL1_TERMINAL_STATE_CODE+0x01);
	/**
	 * trade date offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TRADE_DATE				= (short)(CDOLV_OFF_CDOL1_TVR+0x01);
	/**
	 * trade type offset in CDOL1 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL1_TRADE_TYPE				= (short)(CDOLV_OFF_CDOL1_TRADE_DATE+0x01);
	/**
	 * trade coin code offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TRADE_COIN_CODE			= (short)(CDOLV_OFF_CDOL1_TRADE_TYPE+0x01);
	/**
	 * trade auth money offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY			= (short)(CDOLV_OFF_CDOL2_TRADE_COIN_CODE+0x01);
	/**
	 * random data offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TERMINAL_TRADE_RANDOM	= (short)(CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY+0x01);
	/**
	 * trade other money offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TRADE_OTHER_MONEY		= (short)(CDOLV_OFF_CDOL2_TERMINAL_TRADE_RANDOM+0x01);
	/**
	 * trade state code offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TERMINAL_STATE_CODE		= (short)(CDOLV_OFF_CDOL2_TRADE_OTHER_MONEY+0x01);
	/**
	 * tvr offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TVR						= (short)(CDOLV_OFF_CDOL2_TERMINAL_STATE_CODE+0x01);
	/**
	 * trade date offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TRADE_DATE				= (short)(CDOLV_OFF_CDOL2_TVR+0x01);
	/**
	 * trade type offset in CDOL2 value, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_TRADE_TYPE				= (short)(CDOLV_OFF_CDOL2_TRADE_DATE+0x01);
	/**
	 * second Generate AC command auth code, 0x01 byte
	 */
	private static final short CDOLV_OFF_CDOL2_AUTH_CODE				= (short)(CDOLV_OFF_CDOL2_TRADE_TYPE+0x01);	
	
	private static final short CDOLV_BUF_SIZE							= (short)(CDOLV_OFF_CDOL2_AUTH_CODE+0x01);
	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	
	/**
	 * log sfi, 1 byte
	 */
	private static final short LOG_INFO_OFF_SFI								= 0x00;
	/**
	 * log file record length, 2 byte
	 */
	private static final short LOG_INFO_OFF_RECLEN							= (short) (LOG_INFO_OFF_SFI+0x01);
	/**
	 * log file record number, 1 byte
	 */
	private static final short LOG_INFO_OFF_RECNUM							= (short) (LOG_INFO_OFF_RECLEN+0x02);
	/**
	 * log file content
	 */
	private static final short LOG_INFO_OFF_CONTENT							= (short) (LOG_INFO_OFF_RECNUM+0x01);
	
	/**
	 * extend application file SFI
	 */
	private static final short EXT_APP_FILE_OFF_SFI			= 0x00;
	/**
	 * extend application file type, 01 is normal file, 02 is log file
	 */
	private static final short EXT_APP_FILE_OFF_TYPE		= (short) (EXT_APP_FILE_OFF_SFI+0x01);
	/**
	 * extend application file max file size
	 */
	private static final short EXT_APP_FILE_OFF_MAX_SIZE	= (short) (EXT_APP_FILE_OFF_TYPE+0x01);
	/**
	 * extend application file current file size
	 */
	private static final short EXT_APP_FILE_OFF_CUR_SIZE	= (short) (EXT_APP_FILE_OFF_MAX_SIZE+0x02);
	/**
	 * extend application file max record length
	 */
	private static final short EXT_APP_FILE_OFF_MAX_RECLEN	= (short) (EXT_APP_FILE_OFF_CUR_SIZE+0x02);
	/**
	 * extend application file append record key
	 */
	private static final short EXT_APP_FILE_OFF_OPEN_KEY	= (short) (EXT_APP_FILE_OFF_MAX_RECLEN+0x01);
	/**
	 * extend application file content
	 */
	private static final short EXT_APP_FILE_OFF_CONTENT		= (short) (EXT_APP_FILE_OFF_OPEN_KEY+0x10);
	/**
	 * extend application log file type value
	 */
	//private static final short EXT_APP_FILE_TYPE_NORMAL		= 0x01;
	/**
	 * extend application log file type value
	 */
	private static final short EXT_APP_FILE_TYPE_LOG_FILE	= 0x02;
	/**
	 * extend application file header size
	 */
	private static final short EXT_APP_FILE_HEADLEN_SIZE	= (short) (EXT_APP_FILE_OFF_OPEN_KEY+0x10);
	
	/**
	 * extend application file record content: record length
	 */
	private static final short EXT_APP_RECORD_OFF_LEN      = 0x00;
	/**
	 * extend application file record content: record content modify key
	 */
	private static final short EXT_APP_RECORD_OFF_MNG_KEY  = (short)(EXT_APP_RECORD_OFF_LEN+0x01);
	/**
	 * extend application file record content: record ID
	 */
	private static final short EXT_APP_RECORD_OFF_ID       = (short)(EXT_APP_RECORD_OFF_MNG_KEY+0x10);
	
	
	/**
	 * trade interface, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_TRADE_INTERFACE		= 0x00;
	/**
	 * trade type, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_TRADE_TYPE 			= (short)(TRADE_SESSION_DATA_OFF_TRADE_INTERFACE+0x01);	
	/**
	 * trade life cycle, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_STATE 				= (short)(TRADE_SESSION_DATA_OFF_TRADE_TYPE+0x01); 	
	/**
	 * Generate AC command execute number, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_GAC_CNTR				= (short)(TRADE_SESSION_DATA_OFF_STATE+0x01);
	/**
	 * trade auth near money
	 */
	private static final short TRADE_SESSION_DATA_OFF_TRADE_AUTH_NEAR_MONEY	= (short)(TRADE_SESSION_DATA_OFF_GAC_CNTR+0x01);
	/**
	 * Verify PIN command execute number, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR		= (short)(TRADE_SESSION_DATA_OFF_TRADE_AUTH_NEAR_MONEY+0x06);
	/**
	 * external auth command execute number, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_AUTH_CNTR			= (short)(TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR+0x01);
	/**
	 * External Auth auth code, 2 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE	= (short)(TRADE_SESSION_DATA_OFF_EXT_AUTH_CNTR+0x01);
	/**
	 * qPBOC offline trade coin check, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_QPBOC_OFFLINE_CHECK	= (short)(TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE+0x02);
	/**
	 * CID, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_CID					= (short)(TRADE_SESSION_DATA_OFF_QPBOC_OFFLINE_CHECK+0x01);
	/**
	 * CVR, 3 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_CVR					= (short)(TRADE_SESSION_DATA_OFF_CID+0x01);
	/**
	 * AC, 8 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_AC					= (short)(TRADE_SESSION_DATA_OFF_CVR+0x03);	
	/**
	 * auth ac, used in unwrap and external auth command, 8 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_AUTH_AC				= (short)(TRADE_SESSION_DATA_OFF_AC+0x08);	
	/**
	 * AIP, 2 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_AIP					= (short)(TRADE_SESSION_DATA_OFF_AUTH_AC+0x08);
	/**
	 * extend application trade type, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_APP_TYPE          = (short)(TRADE_SESSION_DATA_OFF_AIP+0x02);   
	/**
	 * extend application last command ins, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_LAST_CMD_INS          = (short)(TRADE_SESSION_DATA_OFF_EXT_APP_TYPE+0x01);
	/**
	 * extend application pre auth trade money, 6 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY		= (short)(TRADE_SESSION_DATA_OFF_LAST_CMD_INS+0x01);
	/**
	 * extend application do rmac, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_SUPPORT_RMAC          = (short)(TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY+0x06);
	/**
	 * 0xDF61, extend application indicate, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE      = (short)(TRADE_SESSION_DATA_OFF_SUPPORT_RMAC+0x01);
	/**
	 * current extend trade file index, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX	= (short)(TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE+0x01);
	/**
	 * current extend trade file offset, 2 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_APP_FILE_OFFSET	= (short)(TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX+0x01);
	/**
	 * current extend trade file sfi, 1 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI		= (short)(TRADE_SESSION_DATA_OFF_EXT_APP_FILE_OFFSET+0x02);
	/**
	 * current extend trade ID, 2 byte
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_APP_CUR_ID		= (short)(TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI+0x01);
	/**
	 * current extend trade pre-auth offset
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_CUR_CONTEXT_OFF	= (short)(TRADE_SESSION_DATA_OFF_EXT_APP_CUR_ID+0x02);
	/**
	 * current extend trade update capp cache len
	 */
	private static final short TRADE_SESSION_DATA_OFF_EXT_APP_CACHE_LEN		= (short)(TRADE_SESSION_DATA_OFF_EXT_CUR_CONTEXT_OFF+0x02);

	private static final short TRADE_SESSION_DATA_BUF_SIZE					= (short)(TRADE_SESSION_DATA_OFF_EXT_APP_CACHE_LEN+0x02);
			
	/**
	 * trade interface-contactless
	 */
	private static final byte TRADE_INTERFACE_CONTACTLESS	= 0x00;
	/**
	 * trade interface-contact
	 */
	private static final byte TRADE_INTERFACE_CONTACT		= 0x01;
	
	// trade type
	//private static final byte TRADE_TYPE_INVALID		= (byte)0xFF;
	/**
	 * trade type - PBOC
	 */
	private static final byte TRADE_TYPE_PBOC			= 0x01;
	/**
	 * trade type - QPBOC
	 */
	private static final byte TRADE_TYPE_QPBOC			= 0x02;
	/**
	 * trade type - EC
	 */
	private static final byte TRADE_TYPE_EC				= 0x04;
	
	
	/**
	 * invalid trade life cycle
	 */
	private static final byte TRADE_STATE_INVALID				= 0x00;
	/**
	 * trade life cycle: select application
	 */
	private static final byte TRADE_STATE_APP_SELECT			= 0x01;
	/**
	 * trade life cycle: application init
	 */
	private static final byte TRADE_STATE_APP_INIT				= 0x02;
	/**
	 * trade life cycle: card auth
	 */
	private static final byte TRADE_STATE_OFF_LINE_AUTH			= 0x03;
	/**
	 * trade life cycle: card action analyse
	 */
	private static final byte TRADE_STATE_CARD_ACTION_ANALYSE	= 0x04;
	/**
	 * trade life cycle: on line
	 */
	private static final byte TRADE_STATE_ON_LINE				= 0x05;
	
	/**
	 * AC Version Value
	 */
	private static final byte AC_VERSION_01		= 0x01;
	//private static final byte AC_VERSION_17		= 0x17;
		
	/**
	 * support contactless PBOC
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_CONTACTLESS_PBOC	= 0x01;
	/**
	 * support contactless qPBOC
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_QPBOC				= 0x02;
	/**
	 * support contact PBOC
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_CONTACT_PBOC		= 0x03;
	/**
	 * terminal only support offline
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_ONLY_OFFLINE		= 0x04;
	/**
	 * support online PIN
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_ONLINE_PIN			= 0x05;
	/**
	 * support signature
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_SIGN				= 0x06;
	/**
	 * request online ARQC
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_REQ_ARQC			= 0x08;
	/**
	 * request CVM
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_REQ_CVM				= 0x09;
	/**
	 * 1– support fDDA 01; 0–support fDDA 00
	 */
	private static final byte TER_TRADE_ATT_OFF_SUPPORT_FDDA_VERSION		= 0x18;
		
	/**
	 * 支持小额检查
	 */
	private static final byte CPP_SUPPORT_EC_CHECK					= 0x00;
	/**
	 * 支持小额和CTTA检查
	 */
	private static final byte CPP_SUPPORT_EC_AND_CTTA_CHECK			= 0x01;
	/**
	 * 支持小额或CTTA检查
	 */
	private static final byte CPP_SUPPORT_EC_OR_CTTA_CHECK			= 0x02;
	/**
	 * 支持新卡检查
	 */
	private static final byte CPP_SUPPORT_NEW_CARD_CHECK			= 0x03;
	/**
	 * 支持PIN重试次数超过检查
	 */
	private static final byte CPP_SUPPORT_PIN_CHECK					= 0x04;
	/**
	 * 允许货币不匹配的脱机交易
	 */
	private static final byte CPP_ALLOW_COIN_NOT_MATCH_OFFLINE		= 0x05;
	/**
	 * 卡优先选择接触式借记/贷记联机 
	 */
	private static final byte CPP_FST_CONTACT_PBOC_ONLINE			= 0x06;
	/**
	 * 返回可用脱机消费金额
	 */
	private static final byte CPP_RETURN_AVAILABLE_MONEY			= 0x07;
	/**
	 * 支持预付
	 */
	private static final byte CPP_PRE_PAY							= 0x08;
	/**
	 * 不允许不匹配货币的交易
	 */
	private static final byte CPP_NOT_ALLOW_COIN_NOT_MATCH_TRADE	= 0x09;
	/**
	 * 如果是新卡且终端仅支持脱机则拒绝交易
	 */
	private static final byte CPP_NEWCARD_ONLY_SUPPORT_OFFLINE		= 0x0A;
	/**
	 * qPBOC脱机批准的交易，卡片记录交易日志
	 */
	private static final byte CPP_QPBOC_SUPPORT_LOG					= 0x0B;
	/**
	 * 匹配货币的交易支持联机PIN
	 */
	private static final byte CPP_MATCH_COIN_TRADE_SUPPORT_PIN		= 0x10;
	/**
	 * 不匹配货币的交易支持联机PIN
	 */
	private static final byte CPP_NOT_MATCH_COIN_TRADE_SUPPORT_PIN	= 0x11;
	/**
	 * 对于不匹配货币交易，卡要求CVM
	 */
	private static final byte CPP_NOT_MATCH_COIN_TRADE_REQUEST_CVM	= 0x12;
	/**
	 * 支持签名
	 */
	private static final byte CPP_SUPPORT_SIGN						= 0x13;
	
	/**
	 * 终止交易
	 */
	private static final byte TRADE_RESULT_ABORT			= 0x00;
	/**
	 * 脱机同意
	 */
	private static final byte TRADE_RESULT_TC			= 0x01;
	/**
	 * 脱机拒绝
	 */
	private static final byte TRADE_RESULT_AAC			= 0x02;
	/**
	 * 联机请求
	 */
	private static final byte TRADE_RESULT_ARQC			= 0x03;
	
	/**
	 * 发卡行认证执行但失败
	 */
	private static final byte CVR_OFF_ISSUE_AUTH_EXEC_FAILED				= 0x04;
	/**
	 * 脱机 PIN执行
	 */
	private static final byte CVR_OFF_OFFLINE_PIN_VERIFY					= 0x05;
	/**
	 * 脱机PIN认证失败
	 */
	private static final byte CVR_OFF_OFFLINE_PIN_FAILED					= 0x06;
	/**
	 * 不能联机
	 */
	private static final byte CVR_OFF_CANNOT_ONLINE						= 0x07;
	/**
	 * 上次联机交易未完成
	 */
	private static final byte CVR_OFF_LAST_ONLINE_TRADE_UNFINISHED		= 0x08;
	/**
	 * PIN锁定
	 */
	private static final byte CVR_OFF_PIN_BLOCKED						= 0x09;
	/**
	 * 频率检查超过
	 */
	private static final byte CVR_OFF_EXCEED_FREQ_CHECK					= 0x0A;
	/**
	 * 新卡
	 */
	private static final byte CVR_OFF_NEW_CARD							= 0x0B;
	/**
	 * 上次联机交易发卡行认证失败
	 */
	private static final byte CVR_OFF_LAST_ONLINE_TRADE_ISSUE_AUTH_FAILED	= 0x0C;
	/**
	 * 联机授权后，发卡行认证没有执行
	 */
	private static final byte CVR_OFF_ONLINE_AUTHED_ISSUE_AUTH_UNEXEC		= 0x0D;
	/**
	 * 由于PIN锁卡片锁定应用
	 */
	private static final byte CVR_OFF_PIN_LOCK_LOCK_APP					= 0x0E;
	/**
	 * 上次交易SDA失败交易拒绝
	 */
	private static final byte CVR_OFF_LAST_TRADE_REFUSE_SDA_FAILED		= 0x0F;
	/**
	 * 上次交易发卡行脚本处理失败
	 */
	private static final byte CVR_OFF_LAST_TRADE_ISSUE_SCRIPT_FAILED	= 0x14;
	/**
	 * 上次交易DDA失败交易拒绝
	 */
	private static final byte CVR_OFF_LAST_TRADE_REFUSE_DDA_FAILED		= 0x15;
	/**
	 * DDA 执行
	 */
	private static final byte CVR_OFF_DDA_EXEC							= 0x16;
	
	/**
	 * 需要联机PIN
	 */
	private static final byte CARD_TRADE_ATTR_NEED_ONLINE_PIN	= 0x00;
	/**
	 * 需要签名
	 */
	private static final byte CARD_TRADE_ATTR_NEED_SIGN			= 0x01;
	
	/**
	 * qPBOC脱机货币检查类型: 小额检查
	 */
	private static final byte QPBOC_OFFLINE_CHECK_TYPE_EC_CHECK				= 0x01;
	/**
	 * qPBOC脱机货币检查类型: 小额和 CTTA 检查
	 */
	private static final byte QPBOC_OFFLINE_CHECK_TYPE_EC_AND_CTTA_CHECK	= 0x02;
	/**
	 * qPBOC脱机货币检查类型: 小额或 CTTA 检查
	 */
	private static final byte QPBOC_OFFLINE_CHECK_TYPE_EC_OR_CTTA_CHECK		= 0x03;
	
	private static final short CURRENT_TRADE_CARD_DATA_BUF_SIZE				= CARD_DATA_OFF_ATC;
	
	/**
	 * 第二个GENERATE AC MASK
	 */
	private static final byte CVR_2ND_GEN_AC_MASK			= (byte) 0xC0;
	/**
	 * 第二个GENERATE AC返回AAC
	 */
	private static final byte CVR_2ND_GEN_AC_RETURN_AAC		= 0x00;
	/**
	 * 第二个GENERATE AC返回TC
	 */
	private static final byte CVR_2ND_GEN_AC_RETURN_TC		= 0x40;
	/**
	 * 不请求第2 个GENERATE AC
	 */
	private static final byte CVR_2ND_GEN_AC_NO_REQ			= (byte) 0x80;
	/**
	 * 第一个GENERATE AC MASK
	 */
	private static final byte CVR_1ST_GEN_AC_MASK			= 0x30; 
	/**
	 * 第一个GENERATE AC返回AAC
	 */
	private static final byte CVR_1ST_GEN_AC_RETURN_AAC		= 0x00;
	/**
	 * 第一个GENERATE AC返回TC
	 */
	private static final byte CVR_1ST_GEN_AC_RETURN_TC		= 0x10;
	/**
	 * 第一个GENERATE AC返回ARQC
	 */
	private static final byte CVR_1ST_GEN_AC_RETURN_ARQC		= 0x20;			
	
	/**
	 * 支持SDA
	 */
	private static final byte AIP_SUPPORT_OFF_SDA			= 0x01;
	/**
	 *  支持DDA
	 */
	private static final byte AIP_SUPPORT_OFF_DDA			= 0x02;
	/**
	 *  支持发卡行认证
	 */
	private static final byte AIP_SUPPORT_OFF_ISSUE_AUTH	= 0x05;
	/**
	 *  支持CDA
	 */
	private static final byte AIP_SUPPORT_OFF_CDA			= 0x07;
	
	/**
	 * DDA header
	 */
	private static final short DDA_OFF_HEADER				= 0x00;
	/**
	 * DDA Signature format
	 */
	private static final short DDA_OFF_SIGN_FORMAT			= (short)(DDA_OFF_HEADER+0x01);
	/**
	 * DDA hash algorithm identifier
	 */
	private static final short DDA_OFF_HASH_IDENTIFIER		= (short)(DDA_OFF_SIGN_FORMAT+0x01);
	/**
	 *  IC卡动态数据长度
	 */
	private static final short DDA_OFF_IC_DATA_LEN			= (short)(DDA_OFF_HASH_IDENTIFIER+0x01);
	/**
	 *  IC卡动态数字长度
	 */
	private static final short DDA_OFF_IC_DATA_DIGIT_LEN	= (short)(DDA_OFF_IC_DATA_LEN+0x01);
	/**
	 *  IC卡动态数字
	 */
	private static final short DDA_OFF_IC_DATA_DIGIT		= (short)(DDA_OFF_IC_DATA_DIGIT_LEN+0x01);	
	/**
	 * 起始填充偏移
	 */
	private static final short DDA_OFF_PADDING_BB			= (short)(DDA_OFF_IC_DATA_DIGIT+0x02);
	
	/**
	 * CDA header, 1 byte
	 */
	private static final short CDA_OFF_HEADER				= 0x00;
	/**
	 * CDA signature format, 1 byte
	 */
	private static final short CDA_OFF_SIGN_FORMAT			= (short)(CDA_OFF_HEADER+0x01);
	/**
	 * CDA Hash algorithm identifier, 1 byte
	 */
	private static final short CDA_OFF_HASH_IDENTIFIER		= (short)(CDA_OFF_SIGN_FORMAT+0x01);
	/**
	 * IC卡动态数据长度, 1 byte
	 */
	private static final short CDA_OFF_IC_DATA_LEN			= (short)(CDA_OFF_HASH_IDENTIFIER+0x01);
	/**
	 * IC卡动态数字长度, 1 byte
	 */
	private static final short CDA_OFF_IC_DATA_DIGIT_LEN	= (short)(CDA_OFF_IC_DATA_LEN+0x01);
	/**
	 * IC卡动态数字, 2 byte
	 */
	private static final short CDA_OFF_IC_DATA_DIGIT		= (short)(CDA_OFF_IC_DATA_DIGIT_LEN+0x01);
	/**
	 * 密文信息数据, 1 byte
	 */
	private static final short CDA_OFF_IC_DATA_CID			= (short)(CDA_OFF_IC_DATA_DIGIT+0x02);
	/**
	 * 应用密文, 8 byte
	 */
	private static final short CDA_OFF_IC_DATA_AC			= (short)(CDA_OFF_IC_DATA_CID+0x01);
	/**
	 * 交易数据hash值, 20 byte
	 */
	private static final short CDA_OFF_IC_TRADE_HASH		= (short)(CDA_OFF_IC_DATA_AC+0x08);
	/**
	 * 起始填充偏移
	 */
	private static final short CDA_OFF_PADDING_BB			= (short)(CDA_OFF_IC_TRADE_HASH+20);
		
	//file operation
	private static final byte CMD_INS_SELECT			= (byte)0xA4;
	private static final byte CMD_INS_READ_RECORD    	= (byte)0xB2;
	private static final byte CMD_INS_UPDATE_RECORD  	= (byte)0xDC;
	//PIN operation
	private static final byte CMD_INS_VERIFY_PIN		= (byte)0x20;
	private static final byte CMD_INS_CHANGE_UNBLOCK_PIN = (byte)0x24;
	//authentication command
	private static final byte CMD_INS_EXTERN_AUTH		= (byte)0x82;
	private static final byte CMD_INS_INTERN_AUTH		= (byte)0x88;
	//lock/unblock application/card command
	private static final byte CMD_INS_APP_BLOCK			= (byte)0x1E;
	private static final byte CMD_INS_APP_UBLOCK		= (byte)0x18;
	private static final byte CMD_INS_CARD_LOCK			= (byte)0x16;
	//trade command
	private static final byte CMD_INS_GENERATE_AC		= (byte)0xAE;	
	private static final byte CMD_INS_GET_DATA			= (byte)0xCA;	
	private static final byte CMD_INS_GPO				= (byte)0xA8;	
	private static final byte CMD_INS_PUT_DATA			= (byte)0xDA;	
	//gp command
	private static final byte CMD_INS_STORE_DATA		= (byte)0xE2;	
	//
	private static final byte CMD_INS_GET_RSP			= (byte)0xC0;

	private static final byte CMD_INS_READ_CAPP_DATA	= (byte)0xB4;
	private static final byte CMD_INS_UPDATE_CAPP_DATA	= (byte)0xDE;
	private static final byte CMD_INS_GET_TRANS_PROVE	= (byte)0x5A;
	
	/**
	 * application life cycle
	 */
	private static final byte APP_STATE_INIT			= 0x01;
	private static final byte APP_STATE_ISSUED			= 0x02;
	private static final byte APP_STATE_LOCKED			= 0x03;
	private static final byte APP_STATE_FOREVER_LOCKED	= 0x04;
	
		
	/**
	 * data not found
	 */
	private static final short SW_REFERENCED_DATA_NOT_FOUND	= (short)0x6A88;
	/**
	 * external auth failed
	 */
	private static final short SW_EXTERNAL_AUTH_FAILED		= (short)0x6300;
	/**
	 * application is blocked
	 */
	private static final short SW_SELECTED_FILE_DEACTIVED	= (short)0x6283;
	/**
	 * PIN Verify Failed
	 */
	private static final short SW_VERIFY_PIN_FAILED			= (short)0x63C0;
	/**
	 * MAC Verify Failed
	 */
	private static final short SW_WRONG_MAC					= (short)0x6988;

	/**
	 * DGI 0D01	
	 */
	private static final short DGI_PERSO_0D01 		= 0x0D01;
	/**
	 * DGI 0E01
	 */
	private static final short DGI_PERSO_0E01 		= 0x0E01;
	
	/**
	 * DES key
	 */
	private static final short DGI_PERSO_8000		= (short)0x8000;
	/**
	 * dCVN DES Key
	 */
	private static final short DGI_PERSO_8001		= (short)0x8001;
	/**
	 * fDDA/DDA CRT ICC Coefficient
	 */
	private static final short DGI_PERSO_8201		= (short)0x8201;
	/**
	 * fDDA/DDA CRT ICC Exponent2 (d mod (q-1))
	 */
	private static final short DGI_PERSO_8202		= (short)0x8202;
	/**
	 * fDDA/DDA CRT ICC Exponent1 (d mod (p-1))
	 */
	private static final short DGI_PERSO_8203		= (short)0x8203;
	/**
	 * fDDA/DDA CRT ICC Prime2(q)
	 */
	private static final short DGI_PERSO_8204		= (short)0x8204;
	/**
	 * fDDA/DDA CRT ICC Prime1(p)
	 */
	private static final short DGI_PERSO_8205		= (short)0x8205;
	
	//PIN
	/**
	 * offline PIN
	 */
	private static final short DGI_PERSO_8010		= (short)0x8010;
	/**
	 * DES KEY Check Value
	 */
	private static final short DGI_PERSO_9000		= (short)0x9000;
	/**
	 * PIN MAX retry counter
	 */
	private static final short DGI_PERSO_9010		= (short)0x9010;
	
	/**
	 * Select FCI (PBOC)
	 */
	private static final short DGI_PERSO_9102		= (short)0x9102;
	/**
	 * Select FCI (QPBOC)
	 */
	private static final short DGI_PERSO_9103 		= (short)0x9103;
	/**
	 * GPO response (PBOC)
	 */
	private static final short DGI_PERSO_9104 		= (short)0x9104;	
	/**
	 * PBOC Issue Application Data
	 */
	private static final short DGI_PERSO_9200		= (short)0x9200;
	/**
	 * GPO response (EC)
	 */
	private static final short DGI_PERSO_9203		= (short)0x9203;
	/**
	 * GPO response (MSD)
	 */
	private static final short DGI_PERSO_9206		= (short)0x9206;
	/**
	 * GPO response (QPBOC)
	 */
	private static final short DGI_PERSO_9207		= (short)0x9207;
	
	/**
	 * Extend application log File
	 */
	private static final short DGI_PERSO_A001		= (short)0xA001;
	private static final short DGI_PERSO_8020		= (short)0x8020;
	private static final short DGI_PERSO_9020		= (short)0x9020;
	
	/**
	 * 0x57, 2磁道等价数据
	 */
	private static final short TAG_2ND_TRACK_DATA						= (short) 0x57;
	/**
	 * 0x82, AIP
	 */
	private static final short TAG_AIP									= (short) 0x82;
	/**
	 * 0x94, AFL
	 */
	private static final short TAG_AFL									= (short) 0x94;
	/**
	 * 卡片风险管理数据对象列表1	
	 */
	private static final short TAG_CDOL1								= (short) 0x8C;
	/**
	 * 卡片风险管理数据对象列表2
	 */
	private static final short TAG_CDOL2								= (short) 0x8D;
	/**
	 * 0x5F2D, 持卡人姓名 
	 */
	private static final short TAG_CARD_HOLDER_NAME						= (short) 0x5F20;
	/**
	 * 0x5F34, 应用PAN序列号
	 */
	private static final short TAG_APP_PAN_SEQUENCE_NO					= (short) 0x5F34;
	/**
	 * 0x9F08, 应用版本号
	 */
	private static final short TAG_APP_VERSION							= (short) 0x9F08;
	/**
	 * 0x9F10, 发卡行应用数据
	 */
	private static final short TAG_ISSUE_APP_DATA						= (short) 0x9F10;
	/**
	 * 上次联机ATC tag
	 */
	private static final short TAG_PREVIOUS_ATC							= (short) 0x9F13;
	/**
	 * 0x9F17, 1 byte, PIN重试计数器
	 */
	private static final short TAG_PIN_RETRY_CNTR						= (short) 0x9F17;
	/**
	 * 0x9F26, 8 byte, 密文数据
	 */
	private static final short TAG_AC									= (short) 0x9F26;
	/**
	 * 密文信息数据
	 */
	private static final short TAG_CID									= (short) 0x9F27;
	/**
	 *  0x9F36, 2 byte, ATC tag
	 */
	private static final short TAG_ATC									= (short) 0x9F36;
	/**
	 * 0x9F37, 4 byte, 不可预知数
	 */
	private static final short TAG_UNFORESEE_NUMBER						= (short) 0x9F37;
	/**
	 * PDOL
	 */
	private static final short TAG_PDOL									= (short) 0x9F38;
	/**
	 * DDOL
	 */
	private static final short TAG_DDOL									= (short) 0x9F49;
	/**
	 * 0x9F4B, signature
	 */
	private static final short TAG_SIGN_DYNAMIC_APP_DATA				= (short) 0x9F4B;
	/**
	 * 0x9F4F, log format
	 */
	private static final short TAG_LOG_FORMAT							= (short) 0x9F4F;
	/**
	 * 0xDF4F, charge log format
	 */
	private static final short TAG_CHARGE_LOG_FORMAT                  	= (short) 0xDF4F;
	/**
	 * 0x9F51, 应用货币代码, 执行频度检查需要  JR/T 0025 专有数据。按GB/T 12406编码 
	 */
	private static final short TAG_APP_COIN_CODE						= (short) 0x9F51;
	/**
	 * 0x9F52, ADA
	 */
	private static final short TAG_APP_DEFAULT_ACTION					= (short) 0x9F52;
	/**
	 * 0x9F53, 连续脱机交易限制数（国际-货币）
	 */
	private static final short TAG_COIN_SEQ_OFFLINE_TRADE_MAX_CNTR 		= (short) 0x9F53;
	/**
	 * 0x9F54, 累计脱机交易金额限制数
	 */
	private static final short TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY		= (short) 0x9F54;
	/**
	 * 0x9F56, 发卡行认证指示位
	 */
	private static final short TAG_ISSUE_AUTH_INDICATE					= (short) 0x9F56;
	/**
	 * 0x9F57, 发卡行国家代码
	 */
	private static final short TAG_ISSUE_STATE_CODE						= (short) 0x9F57;
	/**
	 * 0x9F58, 连续脱机交易下限 
	 */
	private static final short TAG_SEQ_OFFLINE_TRADE_LOWER_LIMIT		= (short) 0x9F58;
	/**
	 * 0x9F59, 连续脱机交易上限 
	 */
	private static final short TAG_SEQ_OFFLINE_TRADE_UPPER_LIMIT		= (short) 0x9F59;
	/**
	 * 0x9F5C, 6 byte, 累计脱机交易金额上限 
	 */
	private static final short TAG_TOTAL_OFFLINE_TRADE_UPPER_LIMIT		= (short) 0x9F5C;
	/**
	 * 0x9F63, 16 byte, 产品标识信息
	 */
	private static final short TAG_PRODUCET_ID_INFO						= (short) 0x9F63;
	/**
	 * 0x9F69, 卡片认证相关数据
	 */
	private static final short TAG_CARD_AUTH_DATA						= (short) 0x9F69;
	/**
	 * 0x9F72, 连续脱机交易限制数（国际-国家）
	 */
	private static final short TAG_STATE_SEQ_OFFLINE_TRADE_MAX_CNTR		= (short) 0x9F72;  
	/**
	 * 0x9F73, 货币转换因子 , 4 byte
	 */
	private static final short TAG_COIN_CONVERT_GENE					= (short) 0x9F73;
	/**
	 * 0x9F75, 累计脱机交易金额限制数（双货币）
	 */
	private static final short TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY_DCOIN	= (short) 0x9F75;
	/**
	 * 0x9F76, 第二应用货币代码 
	 */
	private static final short TAG_SECOND_APP_COIN_CODE					= (short) 0x9F76;	
	/**
	 * 0xDF71, 2 byte, 第二币种电子现金应用货币代码 (EC Secondary  Application Currency Code)
	 */
	private static final short TAG_EC_SECOND_APP_COIN_CODE				= (short)0xDF71;
	/**
	 * 0xDF79, 6 byte, 第二币种电子现金余额(EC Secondary Application Balance)
	 */
	private static final short TAG_EC_SECOND_BALANCE					= (short)0xDF79;
	/**
	 * 0xDF77, 6 byte, 第二币种电子现金余额上限(EC Secondary Application Balance Limit)
	 */
	private static final short TAG_EC_SECOND_BALANCE_LIMIE				= (short)0xDF77;
	/**
	 * 0xDF78, 6 byte, 第二币种电子现金单笔交易限额(EC  Secondary  Application  Single Transaction Limit)
	 */
	private static final short TAG_EC_SECOND_SINGLE_TRADE_LIMIT			= (short)0xDF78;
	/**
	 * 0xDF76, 6 byte, 第二币种电子现金重置阈值(EC Secondary Application Reset Threshold)
	 */
	private static final short TAG_EC_SECOND_RESET_THRESHOLD			= (short)0xDF76;
	/**
	 * 0xDF72, 6 byte, 第二币种卡片 CVM 限额(EC Secondary Card CVM Limit)
	 */
	private static final short TAG_EC_SECOND_CVM_LIMIT					= (short)0xDF72;
	
	
	
	// EC 卡片新增数据元
	/**
	 * 0x9F6D, 电子现金重置阈值
	 */
	private static final short TAG_EC_RESET_THRESHOLD					= (short) 0x9F6D;
	/**
	 * 0x9F77, 电子现金余额上限
	 */
	private static final short TAG_EC_BALANCE_LIMIT						= (short) 0x9F77;
	/**
	 * 0x9F78, 电子现金单笔交易限额
	 */
	private static final short TAG_SINGLE_TRADE_LIMIT					= (short) 0x9F78;
	/**
	 * 0x9F79, 6 byte, 电子现金余额
	 */
	private static final short TAG_EC_BALANCE							= (short) 0x9F79;
	/**
	 * 0xDF60, 1 byte, CAPP交易指示位
	 */
	private static final short TAG_CAPP_INDICATE						= (short) 0xDF60;
	/**
	 * 0xDF61, 1 byte, 分段扣费应用标识
	 */
	private static final short TAG_CAPP_SECTION_PURCHASE_APP_ID			= (short) 0xDF61;
	/**
	 * 0xDF62, 6 byte, 分段扣费抵扣限额
	 */
	private static final short TAG_CAPP_SP_DEDUCTION_LIMIT				= (short) 0xDF62;
	/**
	 * 0xDF63, 6 byte, 电子现金分段扣费已抵扣额
	 */
	private static final short TAG_CAPP_SP_DEDUCTION_MONEY				= (short) 0xDF63;
	
	// 终端数据元
	/**
	 * 0x8A, 授权响应代码, 定义发卡行对交易联机授权的结果  2 byte
	 */
	private static final short TAG_AUTH_CODE							= (short) 0x8A;
	/**
	 * 0x95, TVR 终端验证结果
	 */
	private static final short TAG_TVR									= (short) 0x95;
	/**
	 * 0x9A, 交易日期
	 */
	private static final short TAG_TRADE_DATE							= (short) 0x9A;
	/**
	 * 0x9B, 2 byte, 交易状态信息
	 */
	private static final short TAG_TRADE_STATE_INFO						= (short) 0x9B;
	/**
	 * 0x9C, 交易类型
	 */
	private static final short TAG_TRADE_TYPE							= (short) 0x9C;
	/**
	 * 0x5F2A, 交易货币代码
	 */
	private static final short TAG_TRADE_COIN_CODE						= (short) 0x5F2A;	
	/**
	 * 0x9F02, 6 byte, 交易授权金额
	 */
	private static final short TAG_TRADE_AUTH_MONEY						= (short) 0x9F02;
	/**
	 * 0x9F03, 6 byte, 其它金额
	 */
	private static final short TAG_TRADE_OTHER_MONEY					= (short) 0x9F03;
	/**
	 * 0x9F1A, 终端国家代码
	 */
	private static final short TAG_STATE_CODE							= (short) 0x9F1A;
	/**
	 * 0x9F21, 3 byte, 交易时间
	 */
	private static final short TAG_TRADE_TIME							= (short) 0x9F21;
	
	
	// EC 终端新增数据元
	/**
	 * 0x9F7A, 电子现金终端支持指示器
	 */
	private static final short TAG_EC_TERMINAL_SUPPORT_INDICATE			= (short) 0x9F7A;	
	/**
	 * 0x9F37, 4 byte, 终端不可预知数
	 */
	private static final short TAG_TERMINAL_TRADE_RANDOM				= (short) 0x9F37;
	
	
	// qPBOC卡片新增数据元
	/**
	 * 0x9F5D, 6 byte, 可用脱机消费金额
	 */
	private static final short TAG_AVAILABLE_OFFLINE_MONEY			= (short) 0x9F5D;
	/**
	 * 0x9F68, 4 byte, 卡片附加处理
	 */
	private static final short TAG_CARD_PLUS_PROCESS				= (short) 0x9F68;
	/**
	 * 0x9F6B, 6 byte, 卡片 CVM 限额
	 */
	private static final short TAG_CARD_CVM_LIMIT					= (short) 0x9F6B;
	/**
	 * 0x9F6C, 2 byte, 卡片交易属性
	 */
	private static final short TAG_CARD_TRADE_ATTRIBUTE				= (short) 0x9F6C;
	
	// qPBOC终端新增数据元
	/**
	 * 0x9F66, 终端交易属性
	 */
	private static final short TAG_TERMINAL_TRADE_ATTRIBUTE			= (short) 0x9F66;
	
	
	/**
	 * 0xBF0C, 发卡行自定义数据
	 */
	private static final short TAG_FCI_ISUSSER_DATA					= (short)0xBF0C;
	/**
	 * 0x9F4D, 日志入口
	 */
	private static final short TAG_LOG_ENTRY						= (short)0x9F4D;
	/**
	 * 0xDF4D, 圈存日志入口
	 */
	private static final short TAG_CHARGE_LOG_ENTRY					= (short)0xDF4D;
	/**
	 * 0xDF61, 分段扣费应用标识
	 */
	private static final short TAG_SECTION_PURCHASE_APP_ID			= (short)0xDF61;	
	/**
	 * 0x0001, application version
	 */
	private static final short TAG_GET_APP_VERSION					= (short)0x0001;
	/**
	 * 0x0002, application name
	 */
	private static final short TAG_GET_APP_NAME						= (short)0x0002;
	
	private static final byte GENERATE_AC_TYPE_MASK		= (byte) 0xC0;
	/**
	 *  脱机交易拒绝
	 */
	private static final byte GENERATE_AC_TYPE_AAC		= 0x00;
	/**
	 *  脱机交易同意
	 */
	private static final byte GENERATE_AC_TYPE_TC		= 0x40;
	/**
	 *  请求联机授权
	 */
	private static final byte GENERATE_AC_TYPE_ARQC		= (byte) 0x80;
	/**
	 *  Generate AC指令要求CDA
	 */
	private static final byte GENERATE_AC_CDA			= 0x10;
	
	/**
	 *  1=如果发卡行认证失败，下次联机交易
	 */
	private static final byte ADA_OFF_ISSUE_AUTH_FAILED								= 0x00;
	/**
	 *  1=如果发卡行认证执行但失败，拒绝交易
	 */
	private static final byte ADA_OFF_ISSUE_AUTH_EXEC_FAILED						= 0x01;
	/**
	 *  1=如果发卡行认证必备但没有收到ARPC，拒绝交易
	 */
	private static final byte ADA_OFF_ISSUE_AUTH_M_NO_ARPC							= 0x02;
	/**
	 *  1=如果交易拒绝，生成通知
	 */
	private static final byte ADA_OFF_TRADE_REFUSE									= 0x03;
	/**
	 *  1=如果 PIN 在本次交易中尝试次数超限而且交易拒绝，生成通知 
	 */
	private static final byte ADA_OFF_PIN_VERIFY_EXCEED_AND_TRADE_AAC				= 0x04;
	/**
	 *  1=如果因为发卡行认证失败或没有执行导致交易拒绝，生成通知 
	 */
	private static final byte ADA_OFF_TRADE_REFUST_ISSUE_AUTH_FAILED				= 0x05;
	/**
	 *  1=如果是新卡，联机交易
	 */
	private static final byte ADA_OFF_NEW_CARD										= 0x06;
	/**
	 *  1=如果是新卡，当交易无法联机时拒绝交易
	 */
	private static final byte ADA_OFF_NEW_CARD_CANNOT_ARQC							= 0x07;
	/**
	 *   1=如果 PIN 在本次交易中尝试次数超限，应用锁定
	 */
	private static final byte ADA_OFF_PIN_VERIFY_EXCEED_LOCK_APP					= 0x08;
	/**
	 *  1=如果 PIN 在前次交易中尝试次数超限，拒绝交易
	 */
	private static final byte ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_AAC				= 0x09;
	/**
	 *   1=如果PIN在前次交易中尝试次数超限定，联机交易
	 */
	private static final byte ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_ARQC				= 0x0A;
	/**
	 *  1=如果 PIN 在前次交易中尝试次数超限，当交易无法联机时拒绝交易
	 */
	private static final byte ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_CANNOT_ARQC_AAC	= 0x0B;
	/**
	 *  1=如果发卡行脚本命令在前次交易中失败，联机交易
	 */
	private static final byte ADA_OFF_LAST_TRADE_ISSUE_SCRIPT_FAILED				= 0x0C;
	/**
	 *  1=如果 PIN 在前次交易中尝试次数超限，拒绝交易并锁应用
	 */
	private static final byte ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_AAC_LOCK_APP		= 0x0D;
	
	/**
	 *  CID密文类型 AC TYPE MASK
	 */
	private static final byte CID_AC_TYPE_MASK		= (byte) 0xC0;
	private static final byte CID_AC_TYPE_AAC		= 0x00;
	private static final byte CID_AC_TYPE_TC		= 0x40;
	private static final byte CID_AC_TYPE_ARQC		= (byte) 0x80;

	/**
	 *  CID原因/通知/授权参考码 
	 */
	private static final byte CID_REASON_CODE_MASK			= 0x07;
	/**
	 *  PIN重试超过
	 */
	private static final byte CID_REASON_CODE_PIN_EXCEED	= 0x02;

	/**
	 *  请求通知
	 */
	private static final byte CID_REQUEST_MSG				= 0x08;
	
	// TVR bit offset
	/**
	 * 1=脱机静态数据认证失败
	 */
	private static final byte TVR_BIT_OFFSET_SDA_FAILED	= 0x01;
	/**
	 *  1=机动态数据认证失败
	 */
	private static final byte TVR_BIT_OFFSET_DDA_FAILED	= 0x04;
	/**
	 *  1=复合动态数据认证失败
	 */
	private static final byte TVR_BIT_OFFSET_CDA_FAILED	= 0x05;
	
	private static final byte LOG_VALUE_TYPE_CDOL1	= 0x01;
	private static final byte LOG_VALUE_TYPE_CDOL2	= 0x02;
	private static final byte LOG_VALUE_TYPE_PDOL	= 0x03;
	private static final byte LOG_VALUE_TYPE_CARD	= 0x04;
		
	private static final short CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL	= 0x00;
	private static final short CURRENT_TRADE_CONDITION_OFF_CDOL1		= (short)(CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL+0x01);
	private static final short CURRENT_TRADE_CONDITION_OFF_EXT_TRADE_RESULT	= (short)(CURRENT_TRADE_CONDITION_OFF_CDOL1+0x01);
	private static final short CURRENT_TRADE_CONDITION_OFF_MAC_ERROR	= (short)(CURRENT_TRADE_CONDITION_OFF_EXT_TRADE_RESULT+0x01);
	/**
	 * 双货币电子现金交易标记
	 */
	private static final short CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE	= (short)(CURRENT_TRADE_CONDITION_OFF_MAC_ERROR+0x01);
	private static final short CURRENT_TRADE_CONDITION_SIZE				= (short)(CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE+0x01);
	
	/**
	 * extend application pre-auth context: sfi
	 */
	private static final short EXT_PREAUTH_CONTEXT_OFF_SFI    	= 0x00;
	/**
	 * extend application pre-auth context: ID
	 */
	private static final short EXT_PREAUTH_CONTEXT_OFF_ID		= (short)(EXT_PREAUTH_CONTEXT_OFF_SFI+0x01);
	/**
	 * extend application pre-auth context: trade money
	 */
	private static final short EXT_PREAUTH_CONTEXT_OFF_MONEY	= (short)(EXT_PREAUTH_CONTEXT_OFF_ID+0x02);
	private static final short EXT_PREAUTH_CONTEXT_ITEM_LEN		= (short)(EXT_PREAUTH_CONTEXT_OFF_MONEY+0x06);

	/**
	 * extend application cache buf: file index
	 */
	private static final short EXTAPP_CACHE_OFF_EXT_FILE_INDEX  = 0x00;
	/**
	 * extend application cache buf: file offset
	 */
	private static final short EXTAPP_CACHE_OFF_EXT_FILE_OFFSET	= (short)(EXTAPP_CACHE_OFF_EXT_FILE_INDEX+0x01);
	/**
	 * extend application cache buf: update length
	 */
	private static final short EXTAPP_CACHE_OFF_LEN        		= (short)(EXTAPP_CACHE_OFF_EXT_FILE_OFFSET+0x02);
	/**
	 * extend application cache buf: update context
	 */
	private static final short EXTAPP_CACHE_OFF_CONTENT    		= (short)(EXTAPP_CACHE_OFF_LEN+0x02);
	
	/**
	 * 无效扩展应用交易
	 */
	private static final byte EXTEND_APP_TRADE_TYPE_NOT_SUPPORT   = 0x00;
	/**
	 * 分段扣费交易
	 */
	private static final byte EXTEND_APP_TRADE_TYPE_SP            = 0x01;
	/**
	 * 脱机预授权交易
	 */
	private static final byte EXTEND_APP_TRADE_TYPE_OP            = 0x02;
	/**
	 * 脱机预授权完成交易
	 */
	private static final byte EXTEND_APP_TRADE_TYPE_OPC           = 0x03;
	
	private static final byte[] AUTH_CODE_Y1	= new byte[] {'Y', '1'};
	//private static final byte[] AUTH_CODE_Z1	= new byte[] {'Z', '1'};
	private static final byte[] AUTH_CODE_Y3	= new byte[] {'Y', '3'};
	private static final byte[] AUTH_CODE_Z3	= new byte[] {'Z', '3'};
	private static final byte[] AUTH_CODE_00	= new byte[] {'0', '0'};
	private static final byte[] AUTH_CODE_10	= new byte[] {'1', '0'};
	private static final byte[] AUTH_CODE_11	= new byte[] {'1', '1'};
	private static final byte[] AUTH_CODE_01	= new byte[] {'0', '1'};
	private static final byte[] AUTH_CODE_02	= new byte[] {'0', '2'};
	
	private static final byte[] LOG_INCREASE_VAR	= new byte[] {0x00, 0x00, 0x00, 0x01};
	
	/**
	 * CDOL1 Value/CDOL2 Value offset
	 */
	private static final short terminalDataCDOLTable[] = {
		TAG_TRADE_COIN_CODE,				CDOLV_OFF_CDOL1_TRADE_COIN_CODE,		CDOLV_OFF_CDOL2_TRADE_COIN_CODE,
		TAG_TRADE_AUTH_MONEY,				CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY,		CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY,
		TAG_TERMINAL_TRADE_RANDOM,			CDOLV_OFF_CDOL1_TERMINAL_TRADE_RANDOM,	CDOLV_OFF_CDOL2_TERMINAL_TRADE_RANDOM,
		TAG_TRADE_OTHER_MONEY,				CDOLV_OFF_CDOL1_TRADE_OTHER_MONEY,		CDOLV_OFF_CDOL2_TRADE_OTHER_MONEY,
		TAG_STATE_CODE,						CDOLV_OFF_CDOL1_TERMINAL_STATE_CODE,	CDOLV_OFF_CDOL2_TERMINAL_STATE_CODE,
		
		TAG_TVR,							CDOLV_OFF_CDOL1_TVR,					CDOLV_OFF_CDOL2_TVR,
		TAG_TRADE_DATE,						CDOLV_OFF_CDOL1_TRADE_DATE,				CDOLV_OFF_CDOL2_TRADE_DATE,
		TAG_TRADE_TYPE,						CDOLV_OFF_CDOL1_TRADE_TYPE,				CDOLV_OFF_CDOL2_TRADE_TYPE,
		TAG_AUTH_CODE,						INVALID_VALUE,							CDOLV_OFF_CDOL2_AUTH_CODE,
		
		INVALID_VALUE,						INVALID_VALUE,							INVALID_VALUE
	};
	
	private static final short ANALYSE_TABLE_OFF_TAG		= 0x00;
	private static final short ANALYSE_TABLE_OFF_VALUE_OFF	= 0x01;
	private static final short ANALYSE_TABLE_OFF_LEN		= 0x02;
	
	private static final short ANALYSE_TABLE_ITEM_LEN		= 0x03;
	
	/**
	 * store data analyse table
	 */
	private static final short analyseTable[] = {
		TAG_2ND_TRACK_DATA,						CARD_DATA_OFF_2ND_TRACK_DATA,					20,				// 二磁道等价数据(20 byte),LV struct,tag 57
		TAG_CARD_HOLDER_NAME,					CARD_DATA_OFF_CARD_HOLDER_NAME,					27,				// 持卡人姓名(27 byte)，tag 5F20
		TAG_APP_PAN_SEQUENCE_NO,				CARD_DATA_OFF_PAN,								0x01,			// 应用PAN序列号(1 byte)，tag 5F34		
		TAG_PREVIOUS_ATC,						CARD_DATA_OFF_PREONLINE_ATC,					0x02,			// PreOnlineATC上次联机交易计数器(2 byte),tag 9F13		
		TAG_ATC,								CARD_DATA_OFF_ATC,								0x02,			// ATC交易计数器(2 byte),tag 9F36
		
		TAG_APP_COIN_CODE,						CARD_DATA_OFF_APPCOINCODE,						0x02,			// 应用货币代码(2 byte)，tag 9F51		
		TAG_APP_DEFAULT_ACTION,					CARD_DATA_OFF_ADA,								0x02,			// ADA 应用缺省行为(2 byte)，tag 9F52		
		TAG_COIN_SEQ_OFFLINE_TRADE_MAX_CNTR,	CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT,			0x01,			// 连续脱机交易限制数(国际-货币)(1 byte)，tag 9F53		
		TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY,		CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT,			0x06,			// 累计脱机交易金额限制(6 byte)，tag 9F54		
		TAG_ISSUE_AUTH_INDICATE,				CARD_DATA_OFF_ISSUE_AUTH_INDICATE,				0x01,			// 发卡行认证指示位(1 byte)，tag 9F56
		
		TAG_ISSUE_STATE_CODE,					CARD_DATA_OFF_ISSUE_STATE_CODE,					0x02,			// 发卡行国家代码(2 byte)，tag 9F57
		TAG_SEQ_OFFLINE_TRADE_LOWER_LIMIT,		CARD_DATA_OFF_OFFLINE_CARD_LOWLIMIT,			0x01,			// 连续脱机交易下限(1 byte)，tag 9F58
		TAG_SEQ_OFFLINE_TRADE_UPPER_LIMIT,		CARD_DATA_OFF_OFFLINE_CARD_UPLIMIT,				0x01,			// 连续脱机交易上限(1 byte)，tag 9F59		
		TAG_TOTAL_OFFLINE_TRADE_UPPER_LIMIT,	CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT,			0x06,			// 累计脱机交易金额上限(6 byte)，tag 9F5C		
		TAG_AVAILABLE_OFFLINE_MONEY,			CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY,			0x06,			// 可用脱机消费金额(6 byte), tag 9F5D	
		
		TAG_PRODUCET_ID_INFO,					CARD_DATA_OFF_PRODUCET_ID_INFO,					0x10,			// 产品标识信息(16 byte), tag 9F63 
		TAG_CARD_PLUS_PROCESS,					CARD_DATA_OFF_CARD_PLUS_PROCESS,				0x04,			// 卡片附加处理(4 byte)，tag 9F68
		TAG_CARD_CVM_LIMIT,						CARD_DATA_OFF_CARD_CVM_LIMIT,					0x06,			// 卡片CVM限额(6 byte)，tag 9F6B		
		TAG_CARD_TRADE_ATTRIBUTE,				CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE,				0x02,			// 卡片交易属性(2 byte)，tag 9F6C
		TAG_EC_RESET_THRESHOLD,					CARD_DATA_OFF_EC_RESET_THRESHOLD,				0x06,			// 电子现金重置阈值(6 byte)，tag 9F6D
		
		TAG_STATE_SEQ_OFFLINE_TRADE_MAX_CNTR,	CARD_DATA_OFF_STATE_OFFLINE_CARD_LIMIT,			0x01,			// 连续脱机交易限制数(国际-国家)(1 byte),tag 9F72
		TAG_COIN_CONVERT_GENE,					CARD_DATA_OFF_COIN_CONVERT_GENE,				0x04,			// 货币转换因子(4 byte),tag 9F73
		TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY_DCOIN,CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT,		0x06,			// 累计脱机交易金额限制双货币(6 byte),tag 9F75
		TAG_SECOND_APP_COIN_CODE,				CARD_DATA_OFF_SECOND_APP_COIN_CODE,				0x02,			// 第二应用货币代码(2 byte),tag 9F76		
		TAG_EC_BALANCE_LIMIT,					CARD_DATA_OFF_EC_BALANCE_UPLIMIT,				0x06,			// 电子现金余额上限(6 byte),tag 9F77

		TAG_SINGLE_TRADE_LIMIT,					CARD_DATA_OFF_SINGLE_CARD_LIMIT,				0x06,			// 电子现金单笔交易限额(6 byte),tag 9F78
		TAG_EC_BALANCE,							CARD_DATA_OFF_EC_BALANCE,						0x06,			// 电子现金余额(6 byte), tag 9F79
		TAG_CAPP_SP_DEDUCTION_LIMIT,			CARD_DATA_OFF_SP_DEDUCTION_LIMIT,				0x06,			// 电子现金分段扣费抵扣限额(6 byte), tag 0xDF62 
		TAG_CAPP_SP_DEDUCTION_MONEY,			CARD_DATA_OFF_SP_DEDUCTION_MONEY,				0x06,			// 电子现金分段扣费已抵扣额(6 byte), tag 0xDF63 
		TAG_EC_SECOND_APP_COIN_CODE,			CARD_DATA_OFF_EC_SECOND_APP_COIN_CODE,			0x02,			// 0xDF71, 2 byte, 第二币种电子现金应用货币代码

		TAG_EC_SECOND_CVM_LIMIT,				CARD_DATA_OFF_EC_SECOND_CVM_LIMIT,				0x06,			// 0xDF72, 6 byte, 第二币种卡片 CVM 限额
		TAG_EC_SECOND_RESET_THRESHOLD,			CARD_DATA_OFF_EC_SECOND_RESET_THRESHOLD,		0x06,			// 0xDF76, 6 byte, 第二币种电子现金重置阈值
		TAG_EC_SECOND_BALANCE_LIMIE,			CARD_DATA_OFF_EC_SECOND_BALANCE_LIMIE,			0x06,			// 0xDF77, 6 byte, 第二币种电子现金余额上限
		TAG_EC_SECOND_SINGLE_TRADE_LIMIT,		CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT,		0x06,			// 0xDF78, 6 byte, 第二币种电子现金单笔交易限额
		TAG_EC_SECOND_BALANCE,					CARD_DATA_OFF_EC_SECOND_BALANCE,				0x06,			// 0xDF79, 6 byte, 第二币种电子现金余额
		
		INVALID_VALUE,							INVALID_VALUE,									INVALID_VALUE
	};	
	
	/**
	 * get data command allow table
	 */
	private static short getDataTags[] = {
		TAG_PREVIOUS_ATC,							CARD_DATA_OFF_PREONLINE_ATC,					(short)0x02,
		TAG_PIN_RETRY_CNTR,							INVALID_VALUE,									INVALID_VALUE,
		TAG_ATC,									CARD_DATA_OFF_ATC,								(short)0x02,
		TAG_LOG_FORMAT,								INVALID_VALUE,									INVALID_VALUE,
		TAG_APP_COIN_CODE,							CARD_DATA_OFF_APPCOINCODE,						(short)0x02,
		
		TAG_APP_DEFAULT_ACTION,						CARD_DATA_OFF_ADA,								(short)0x02,
		TAG_COIN_SEQ_OFFLINE_TRADE_MAX_CNTR,		CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT,			(short)0x01,
		TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY,			CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT,			(short)0x06,
		TAG_ISSUE_AUTH_INDICATE,					CARD_DATA_OFF_ISSUE_AUTH_INDICATE,				(short)0x01,
		TAG_ISSUE_STATE_CODE,						CARD_DATA_OFF_ISSUE_STATE_CODE,					(short)0x02,
		
		TAG_SEQ_OFFLINE_TRADE_LOWER_LIMIT,			CARD_DATA_OFF_OFFLINE_CARD_LOWLIMIT,			(short)0x01,
		TAG_SEQ_OFFLINE_TRADE_UPPER_LIMIT,			CARD_DATA_OFF_OFFLINE_CARD_UPLIMIT,				(short)0x01,
		TAG_TOTAL_OFFLINE_TRADE_UPPER_LIMIT,		CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT,			(short)0x06,
		TAG_AVAILABLE_OFFLINE_MONEY,				CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY,			(short)0x06,
		TAG_CARD_PLUS_PROCESS,						CARD_DATA_OFF_CARD_PLUS_PROCESS,				(short)0x04,
		
		TAG_CARD_CVM_LIMIT,							CARD_DATA_OFF_CARD_CVM_LIMIT,					(short)0x06,
		TAG_EC_RESET_THRESHOLD,						CARD_DATA_OFF_EC_RESET_THRESHOLD,				(short)0x06,		
		TAG_STATE_SEQ_OFFLINE_TRADE_MAX_CNTR,		CARD_DATA_OFF_STATE_OFFLINE_CARD_LIMIT,			(short)0x01,
		TAG_COIN_CONVERT_GENE,						CARD_DATA_OFF_COIN_CONVERT_GENE,				(short)0x04,
		TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY_DCOIN,	CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT,		(short)0x06,
		
		TAG_SECOND_APP_COIN_CODE,					CARD_DATA_OFF_SECOND_APP_COIN_CODE,				(short)0x02,
		TAG_EC_BALANCE_LIMIT,						CARD_DATA_OFF_EC_BALANCE_UPLIMIT,				(short)0x06,		
		TAG_SINGLE_TRADE_LIMIT,						CARD_DATA_OFF_SINGLE_CARD_LIMIT,				(short)0x06,
		TAG_EC_BALANCE,								CARD_DATA_OFF_EC_BALANCE,						(short)0x06,
		TAG_CHARGE_LOG_FORMAT,						INVALID_VALUE,									INVALID_VALUE,
		
		TAG_CAPP_SECTION_PURCHASE_APP_ID,			INVALID_VALUE,									(short)0x01,
		TAG_CAPP_SP_DEDUCTION_LIMIT,				CARD_DATA_OFF_SP_DEDUCTION_LIMIT,				(short)0x06,
		TAG_CAPP_SP_DEDUCTION_MONEY,				CARD_DATA_OFF_SP_DEDUCTION_MONEY,				(short)0x06,
		
		TAG_EC_SECOND_APP_COIN_CODE,				CARD_DATA_OFF_EC_SECOND_APP_COIN_CODE,			(short)0x02,
		TAG_EC_SECOND_CVM_LIMIT,					CARD_DATA_OFF_EC_SECOND_CVM_LIMIT,				(short)0x06,
		TAG_EC_SECOND_RESET_THRESHOLD,				CARD_DATA_OFF_EC_SECOND_RESET_THRESHOLD,		(short)0x06,
		TAG_EC_SECOND_BALANCE_LIMIE,				CARD_DATA_OFF_EC_SECOND_BALANCE_LIMIE,			(short)0x06,
		TAG_EC_SECOND_SINGLE_TRADE_LIMIT,			CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT,		(short)0x06,
		TAG_EC_SECOND_BALANCE,						CARD_DATA_OFF_EC_SECOND_BALANCE,				(short)0x06,
		
		TAG_GET_APP_VERSION,						INVALID_VALUE,									INVALID_VALUE,
		TAG_GET_APP_NAME,							INVALID_VALUE,									INVALID_VALUE,
		
		INVALID_VALUE,								INVALID_VALUE,									INVALID_VALUE
	};
	
	/**
	 * put data command allow table
	 */
	private static short putDataTags[] = {
		TAG_COIN_SEQ_OFFLINE_TRADE_MAX_CNTR,		CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT,			(short)0x01,
		TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY,			CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT,			(short)0x06,
		TAG_SEQ_OFFLINE_TRADE_LOWER_LIMIT,			CARD_DATA_OFF_OFFLINE_CARD_LOWLIMIT,			(short)0x01,
		TAG_SEQ_OFFLINE_TRADE_UPPER_LIMIT,			CARD_DATA_OFF_OFFLINE_CARD_UPLIMIT,				(short)0x01,
		TAG_TOTAL_OFFLINE_TRADE_UPPER_LIMIT,		CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT,			(short)0x06,
		
		TAG_CARD_CVM_LIMIT,							CARD_DATA_OFF_CARD_CVM_LIMIT,					(short)0x06,
		TAG_EC_RESET_THRESHOLD,						CARD_DATA_OFF_EC_RESET_THRESHOLD,				(short)0x06,
		TAG_STATE_SEQ_OFFLINE_TRADE_MAX_CNTR,		CARD_DATA_OFF_STATE_OFFLINE_CARD_LIMIT,			(short)0x01,
		TAG_COIN_CONVERT_GENE,						CARD_DATA_OFF_COIN_CONVERT_GENE,				(short)0x04,
		TAG_TOTAL_OFFLINE_TRADE_MAX_MONEY_DCOIN,	CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT,		(short)0x06,
		
		TAG_EC_BALANCE_LIMIT,						CARD_DATA_OFF_EC_BALANCE_UPLIMIT,				(short)0x06,
		TAG_SINGLE_TRADE_LIMIT,						CARD_DATA_OFF_SINGLE_CARD_LIMIT,				(short)0x06,
		TAG_EC_BALANCE,								CARD_DATA_OFF_EC_BALANCE,						(short)0x06,
		TAG_CAPP_SECTION_PURCHASE_APP_ID,			INVALID_VALUE,									(short)0x01,
		TAG_CAPP_SP_DEDUCTION_LIMIT,				CARD_DATA_OFF_SP_DEDUCTION_LIMIT,				(short)0x06,
				
		TAG_EC_SECOND_CVM_LIMIT,					CARD_DATA_OFF_EC_SECOND_CVM_LIMIT,				(short)0x06,
		TAG_EC_SECOND_RESET_THRESHOLD,				CARD_DATA_OFF_EC_SECOND_RESET_THRESHOLD,		(short)0x06,
		TAG_EC_SECOND_BALANCE_LIMIE,				CARD_DATA_OFF_EC_SECOND_BALANCE_LIMIE,			(short)0x06,
		TAG_EC_SECOND_SINGLE_TRADE_LIMIT,			CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT,		(short)0x06,
		TAG_EC_SECOND_BALANCE,						CARD_DATA_OFF_EC_SECOND_BALANCE,				(short)0x06,
		
		INVALID_VALUE,								INVALID_VALUE,									INVALID_VALUE
	};
	
	private static final byte INVALID_RECORD_OBJECT_INDEX	= (byte)0xFF;
	private static final short INVALID_RECORD_MAP_VALUE		= 0x00;
	private static final byte RECORD_OBJECT_SIZE			= 30;
	
	/**
	 * normal file record object array
	 */
	private Object[] recordObj;
	/**
	 * normal file record map
	 */
	private short[] recordMap;
	/**
	 * Temp variable for STORE-DATA P2.
	 * It's not use RAM because Perso is a small quantity of operation.
	 */
	private byte blockNum;
	/**
	 * RAM Cache flag, true means use RAM cache buf, false means use flash cache buf
	 */
	private static final boolean RAM_CACHE = false;
	
	private static final short MAX_FAILED_COUNTER = 100;
	
	/**
	 * init variables
	 */
	private void initVariables() {
		short i;
				
		Util.arrayFillNonAtomic(paramBuf, (short) 0x00, PBOC_PARAM_BUF_SIZE, (byte) 0x00);
		Util.arrayFillNonAtomic(cardDataBuf, (short) 0x00, CARD_DATA_BUF_SIZE, (byte) 0x00);
		// if value equal 0xFF means tag not perso
		Util.arrayFillNonAtomic(cardDataBuf, CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT, (short) 0x04, (byte) 0xFF);		
		
		for (i=0x00; i<RECORD_OBJECT_SIZE; i++) {
			recordMap[i] = INVALID_RECORD_MAP_VALUE;
		}
				
		appState = APP_STATE_INIT;					
		
		sQPBOCARQCAACRspATCOff = INVALID_VALUE;
		sQPBOCARQCAACRspIssueAPPOff = INVALID_VALUE;
		sQPBOCARQCAACRspACOff = INVALID_VALUE;
		sQPBOCARQCAACRspCardAttrOff = INVALID_VALUE;
		sQPBOCARQCAACRspAvailMoneyOff = INVALID_VALUE;
		
		sQPBOCTCRspATCOff = INVALID_VALUE;
		sQPBOCTCRspACOff = INVALID_VALUE;
		sQPBOCTCRspIssueAppOff = INVALID_VALUE;
		sQPBOCTCRspICCSIGOff = INVALID_VALUE;
		sQPBOCTCRspCardAttrOff = INVALID_VALUE;
		sQPBOCTCRspAvailMoneyOff = INVALID_VALUE;
		
		sExtAppIndicateOff = INVALID_VALUE;
	}
	
	/**
	 * Constructor of PBOC. create storage and set state machine.
	 */
	private PBOC() {		
		maxAppletNum++;
		cardState[0x00] = CARD_STATE_INIT;
		
		recordObj = new Object[RECORD_OBJECT_SIZE];
		recordMap = new short[RECORD_OBJECT_SIZE];				
		
		cardDataBuf = new byte[CARD_DATA_BUF_SIZE];
		paramBuf = new byte[PBOC_PARAM_BUF_SIZE];		
		terDataInCDOLVOff = new byte[CDOLV_BUF_SIZE];
		
		abyPBOCTradeSession = JCSystem.makeTransientByteArray(TRADE_SESSION_DATA_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
		if (FUNCTION_FOR_TIANYU) {
			abyCurTradeCardData = JCSystem.makeTransientByteArray(CURRENT_TRADE_CARD_DATA_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
			sessionKey = JCSystem.makeTransientByteArray((short)0x10, JCSystem.CLEAR_ON_RESET);
			tripleDesKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.LENGTH_DES3_2KEY, false);
			curTradeConditions = JCSystem.makeTransientBooleanArray(CURRENT_TRADE_CONDITION_SIZE, JCSystem.CLEAR_ON_RESET);
		} else {
			abyCurTradeCardData = JCSystem.makeTransientByteArray(CURRENT_TRADE_CARD_DATA_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
			sessionKey = JCSystem.makeTransientByteArray((short)0x10, JCSystem.CLEAR_ON_DESELECT);
			tripleDesKey = (DESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_DES3_2KEY, false);
			curTradeConditions = JCSystem.makeTransientBooleanArray(CURRENT_TRADE_CONDITION_SIZE, JCSystem.CLEAR_ON_DESELECT);
		}
		
		tripleDesKey.setKey(sessionKey, (short)0x00);		
		signMac = Signature.getInstance(Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
		signMac.init(tripleDesKey, Signature.MODE_SIGN);
		cipherECBEncrypt = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		cipherECBEncrypt.init(tripleDesKey, Cipher.MODE_ENCRYPT);
		cipherECBDecrypt = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD, false);
		cipherECBDecrypt.init(tripleDesKey, Cipher.MODE_DECRYPT);
		msgDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);			
		cipherRSA = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		
		initVariables();
		
		backRecord = new byte[0x102];
	}
	
	/**
	 * Install method, called by JCRE when installed.
	 * @param bArray	Install parameters.
	 * @param bOffset	offset of parameters.
	 * @param bLength	length of parameters.
	 */
	public static void install(byte[] bArray, short bOffset, byte bLength) {		
		new PBOC().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
		//PBOC.sc = GPSystem.getSecureChannel();
	}
	
	/**
	 * get free record space 
	 * @return
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
	 * find tag in analyse table
	 * @param sTag specifial tag
	 * @return analyse table index
	 */
	private static short findTagInAnalyseTable(short sTag) {				
		for (short i = 0x00; analyseTable[(short)(i+ANALYSE_TABLE_OFF_TAG)] != INVALID_VALUE; i += ANALYSE_TABLE_ITEM_LEN) {			
			if (analyseTable[(short)(i+ANALYSE_TABLE_OFF_TAG)] == sTag) {
				return i;
			}			
		}
		
		return INVALID_VALUE;
	}
	
	/**
	 * analyse perso data
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void analyseRecordData(short dgi, byte[] cmdbuf, short sOff, short sLen) {
		
		short sTag;
		short sValueLen;
		short sIndex;
		short sTmp;
		
		sTmp = sOff;
		sLen += sOff;
		if ((dgi != DGI_PERSO_0D01)
			&& (dgi != DGI_PERSO_0E01)) {
			// skip tag 0x70 and length byte
			sOff++;
			if (cmdbuf[sOff++] == (byte) 0x81) {
				sOff++;
			}
		}
				
		while (sOff < sLen) {
			sTag = (short)(cmdbuf[sOff++]&0x00FF);
			if ((short)(sTag&0x001F) == (short) 0x001F) {
				sTag <<= 8;
				sTag |= (short)(cmdbuf[sOff++]&0x00FF);
			}
			
			sValueLen = (short)(cmdbuf[sOff++]&0x00FF);
			if (sValueLen == (short)0x81) {
				sValueLen = (short)(cmdbuf[sOff++]&0x00FF);
			}
						
			sIndex = findTagInAnalyseTable(sTag);
			
			if (sIndex == INVALID_VALUE) {
				// signature
				if (sTag == TAG_SIGN_DYNAMIC_APP_DATA) {					
					sQPBOCSigDGI = dgi;
					sQPBOCSigOff = (short)(sOff-sTmp);
				} else if (sTag == TAG_CDOL1) {
					short sCDOLValueLen = PBOCUtil.getValueLenByTLList(cmdbuf, sOff, sValueLen);
					cdol1 = new byte[sValueLen];
					Util.arrayCopy(cmdbuf, sOff, cdol1, (short)0x00, sValueLen);
					if (FUNCTION_FOR_TIANYU) {
						cdol1Value = JCSystem.makeTransientByteArray(sCDOLValueLen, JCSystem.CLEAR_ON_RESET);
					} else {
						cdol1Value = JCSystem.makeTransientByteArray(sCDOLValueLen, JCSystem.CLEAR_ON_DESELECT);
					}
				} else if (sTag == TAG_CDOL2) {
					short sCDOLValueLen = PBOCUtil.getValueLenByTLList(cmdbuf, sOff, sValueLen);
					cdol2 = new byte[sValueLen];
					Util.arrayCopy(cmdbuf, sOff, cdol2, (short)0x00, sValueLen);
					if (FUNCTION_FOR_TIANYU) {
						cdol2Value = JCSystem.makeTransientByteArray(sCDOLValueLen, JCSystem.CLEAR_ON_RESET);
					} else {
						cdol2Value = JCSystem.makeTransientByteArray(sCDOLValueLen, JCSystem.CLEAR_ON_DESELECT);
					}
				} else if (sTag == TAG_DDOL) {
					paramBuf[PBOC_PARAM_OFF_DDOLVALUE_LEN] = (byte)PBOCUtil.getValueLenByTLList(cmdbuf, sOff, sValueLen);					
				} else if (sTag == TAG_LOG_FORMAT) {
					logFormat = new byte[sValueLen];
					Util.arrayCopy(cmdbuf, sOff, logFormat, (short)0x00, sValueLen);
				} else if (sTag == TAG_CHARGE_LOG_FORMAT) {
					chargelogFormat = new byte[sValueLen];
					Util.arrayCopy(cmdbuf, sOff, chargelogFormat, (short)0x00, sValueLen);
				} else if (sTag == TAG_APP_VERSION) {
					short appVersion = Util.getShort(cmdbuf, sOff);
					bIsPBOC3 = (boolean)(appVersion == 0x00 || appVersion == 0x30);
				}
				
				sOff += sValueLen;
				continue;
			}
			
			if ((sTag == TAG_2ND_TRACK_DATA) || (sTag == TAG_CARD_HOLDER_NAME)) {				
				// compare length
				if ((short) (sValueLen+1) > analyseTable[(short)(sIndex+ANALYSE_TABLE_OFF_LEN)]) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				// LV Struct, write L
				cardDataBuf[analyseTable[(short)(sIndex+ANALYSE_TABLE_OFF_VALUE_OFF)]] = (byte) sValueLen;
				// write Value
				Util.arrayCopy(cmdbuf, sOff, cardDataBuf, (short) (analyseTable[(short)(sIndex+ANALYSE_TABLE_OFF_VALUE_OFF)]+1), sValueLen);							
			} else {				
				if (sValueLen > (short) (analyseTable[(short)(sIndex+ANALYSE_TABLE_OFF_LEN)]&0x00FF)) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				// 9F5D
				if (sTag == TAG_AVAILABLE_OFFLINE_MONEY) {
					sQPBOC9F5DDGI = dgi;
					sQPBOC9F5DOff = (short)(sOff-sTmp);					
				}
				
				// write data
				Util.arrayCopy(cmdbuf, sOff, cardDataBuf, (short) (analyseTable[(short)(sIndex+ANALYSE_TABLE_OFF_VALUE_OFF)]&0x00FF), sValueLen);
			}
			
			sOff += sValueLen;
		}		
	}
	
	/**
	 * perso Record File.
	 * @param dgi		DGI of perso data, should be sfi+num.
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void persoRecContent(short dgi, byte[] cmdbuf, short sOff, short sLen) {
		byte index;
		byte[] record;
		short recordLen;
		if (persoDGI == 0x00) {
			index = getFreeRecTableIndex();
			// not enough record table space
			if (index == INVALID_RECORD_OBJECT_INDEX) {
				ISOException.throwIt(ISO7816.SW_FILE_FULL);
			}
			
			if ((dgi != DGI_PERSO_0D01) && (dgi != DGI_PERSO_0E01)) {
				recordLen = (short)(cmdbuf[(short)(sOff+0x01)]&0x0FF);
				if (recordLen == 0x81) {
					recordLen = (short)(cmdbuf[(short)(sOff+0x02)]&0x0FF);
					recordLen += 0x03;
				} else {
					recordLen += 0x02;
				}
				if (recordLen > 0x100) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
			} else {
				recordLen = sLen;
			}
			
			record = new byte[recordLen];
			recordObj[index] = record;
			recordMap[index] = dgi;
		} else {
			for (index=0x00; index<RECORD_OBJECT_SIZE; index++) {
				if (recordMap[index] == dgi) {
					break;
				}
			}			
			
			record = (byte[])recordObj[index];
			recordLen = (short)record.length;
		}
		
		short tmp = (short)(persoDGIOff + sLen);
		if (tmp > recordLen) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		// save record data
		Util.arrayCopy(cmdbuf, sOff, record, persoDGIOff, sLen);
		
		if (tmp == recordLen) {
			// check length
			if (dgi != DGI_PERSO_0D01 && dgi != DGI_PERSO_0E01) {
				sLen = (short)(record[0x01]&0x0FF);
				if (sLen == 0x81) {
					sLen = (short)(record[0x02]&0x0FF);
					sLen++;
				}
				sLen += 0x02;
				if (sLen != recordLen) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}	
			}
			
			analyseRecordData(dgi, record, (short)0x00, recordLen);
			persoDGI = persoDGIOff = 0x00;
		} else {
			persoDGI = dgi;
			persoDGIOff = tmp;
		}
	}
	
	/**
	 * perso rsa CRT key
	 * @param dgi		DGI of perso data.
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void persoRSACRTKey(short dgi, byte[] cmdbuf, short sOff, short sLen) {							
		if (priCRTKey == null) {
			priCRTKey = (RSAPrivateCrtKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_CRT_PRIVATE, (short)(sLen*16), false);			
		}
		
		switch (dgi) {
		case DGI_PERSO_8201:
			priCRTKey.setPQ(cmdbuf, sOff, sLen);
			break;
		case DGI_PERSO_8202:
			priCRTKey.setDQ1(cmdbuf, sOff, sLen);
			break;
		case DGI_PERSO_8203:
			priCRTKey.setDP1(cmdbuf, sOff, sLen);
			break;
		case DGI_PERSO_8204:
			priCRTKey.setQ(cmdbuf, sOff, sLen);
			break;
		case DGI_PERSO_8205:
			priCRTKey.setP(cmdbuf, sOff, sLen);
			break;
		}

		if (priCRTKey.isInitialized()) {
			try {				
				cipherRSA.init(priCRTKey, Cipher.MODE_ENCRYPT);
			} catch (CryptoException e) {				
				switch (e.getReason()) {
				case CryptoException.ILLEGAL_VALUE:
					ISOException.throwIt((short)(0x9E00 | CryptoException.ILLEGAL_VALUE));
				case CryptoException.UNINITIALIZED_KEY:
					ISOException.throwIt((short)(0x9E00 | CryptoException.UNINITIALIZED_KEY));
				case CryptoException.NO_SUCH_ALGORITHM:
					ISOException.throwIt((short)(0x9E00 | CryptoException.NO_SUCH_ALGORITHM));
				case CryptoException.INVALID_INIT:
					ISOException.throwIt((short)(0x9E00 | CryptoException.INVALID_INIT));
				case CryptoException.ILLEGAL_USE:
					ISOException.throwIt((short)(0x9E00 | CryptoException.ILLEGAL_USE));
				default:
					ISOException.throwIt((short)(0x9E10));
				}
			} catch (SystemException e) {
				if (SystemException.NO_TRANSIENT_SPACE == e.getReason()) {
					ISOException.throwIt((short)(0x6A84));
				} else {
					ISOException.throwIt((short)(0x9E11));
				}
			} catch (ISOException e) {
				ISOException.throwIt(e.getReason());
			} catch (TransactionException e) {
				ISOException.throwIt((short)(0x9E13));
			} catch (Exception e) {
				ISOException.throwIt((short)(0x9E15));
			}
		}		
	}
	
	/**
	 * get the terminal data in PBOC/QPBOC PDOL Value's offset in GPO command 
	 */
	private void getTerminalDataOffInPODLValue() {		
		if (qpbocpdol != null) {
			short qpbocpdolLen = (short)qpbocpdol.length;
			
			sQPDOLECTerSupportIndicateOff = PBOCUtil.findValuePosInTLList(TAG_EC_TERMINAL_SUPPORT_INDICATE, qpbocpdol, (short)0x00, qpbocpdolLen);
			sQPDOLVTerminalTradeAttrOff = PBOCUtil.findValuePosInTLList(TAG_TERMINAL_TRADE_ATTRIBUTE, qpbocpdol, (short)0x00, qpbocpdolLen);
			sQPDOLTradeCoinCodeOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_COIN_CODE, qpbocpdol, (short)0x00, qpbocpdolLen);
			sQPDOLTradeAuthMoneyOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_AUTH_MONEY, qpbocpdol, (short)0x00, qpbocpdolLen);			
			sQPDOLTerminalTradeRandomOff = PBOCUtil.findValuePosInTLList(TAG_UNFORESEE_NUMBER, qpbocpdol, (short)0x00, qpbocpdolLen);			
			sQPDOLTradeOtherMoneyOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_OTHER_MONEY, qpbocpdol, (short)0x00, qpbocpdolLen);			
			sQPDOLTerminalStateCodeOff = PBOCUtil.findValuePosInTLList(TAG_STATE_CODE, qpbocpdol, (short)0x00, qpbocpdolLen);			
			sQPDOLTerminalResultOff = PBOCUtil.findValuePosInTLList(TAG_TVR, qpbocpdol, (short)0x00, qpbocpdolLen);			
			sQPDOLTradeDateOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_DATE, qpbocpdol, (short)0x00, qpbocpdolLen);			
			sQPDOLTradeTypeOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_TYPE, qpbocpdol, (short)0x00, qpbocpdolLen);			
			sQPDOLCAPPIndicateOff = PBOCUtil.findValuePosInTLList(TAG_CAPP_INDICATE, qpbocpdol, (short)0x00, qpbocpdolLen);
		} else {
			sQPDOLECTerSupportIndicateOff = INVALID_VALUE;
			sQPDOLVTerminalTradeAttrOff = INVALID_VALUE;
			sQPDOLTradeCoinCodeOff = INVALID_VALUE;
			sQPDOLTradeAuthMoneyOff = INVALID_VALUE;
			sQPDOLTerminalTradeRandomOff = INVALID_VALUE;
			sQPDOLTradeOtherMoneyOff = INVALID_VALUE;
			sQPDOLTerminalStateCodeOff = INVALID_VALUE;
			sQPDOLTerminalResultOff = INVALID_VALUE;
			sQPDOLTradeDateOff = INVALID_VALUE;
			sQPDOLTradeTypeOff = INVALID_VALUE;
			sQPDOLCAPPIndicateOff = INVALID_VALUE;
		}
		
		if (pbocpdol != null) {
			short pbocpdolLen = (short)pbocpdol.length;
			
			sPPDOLECTerSupportIndicateOff = PBOCUtil.findValuePosInTLList(TAG_EC_TERMINAL_SUPPORT_INDICATE, pbocpdol, (short)0x00, pbocpdolLen);
			sPPDOLTradeCoinCodeOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_COIN_CODE, pbocpdol, (short)0x00, pbocpdolLen);
			sPPDOLTradeAuthMoneyOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_AUTH_MONEY, pbocpdol, (short)0x00, pbocpdolLen);
		} else {
			sPPDOLECTerSupportIndicateOff = INVALID_VALUE;
			sPPDOLTradeCoinCodeOff = INVALID_VALUE;
			sPPDOLTradeAuthMoneyOff = INVALID_VALUE;
		}		
	}
	
	/**
	 * get the terminal data in CDOL Value's offset 
	 */
	private void getTerminalDataOffInCDOLValue() {
		short cdol1Len = (short)cdol1.length;
		short cdol2Len = (short)cdol2.length;
		
		for (short i=0x00; terminalDataCDOLTable[i] != INVALID_VALUE; i+=0x03) {
			if (terminalDataCDOLTable[(short)(i+0x01)] != INVALID_VALUE) {
				terDataInCDOLVOff[terminalDataCDOLTable[(short)(i+0x01)]] = (byte)PBOCUtil.findValuePosInTLList(terminalDataCDOLTable[i], cdol1, (short)0x00, cdol1Len);	
			}
			
			if (terminalDataCDOLTable[(short)(i+0x02)] != INVALID_VALUE) {
				terDataInCDOLVOff[terminalDataCDOLTable[(short)(i+0x02)]] = (byte)PBOCUtil.findValuePosInTLList(terminalDataCDOLTable[i], cdol2, (short)0x00, cdol2Len);	
			}			
		}
	}
	
	/**
	 * perso FCI data
	 * @param dgi		DGI of perso data.
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void persoFCI(short dgi, byte[] cmdbuf, short sOff, short sLen) {
		short sTmp;
		byte[] fci;
		short sfciOff;
		short sfciLen;
		// get aid
		sTmp = JCSystem.getAID().getBytes(cmdbuf, (short) (sOff+sLen));
		
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
		Util.arrayCopy(cmdbuf, sOff, fci, sfciOff, sLen);
		
		// skip A5 Tag
		sOff++;
		// skip A5 Length byte
		sLen = (short) (cmdbuf[sOff++]&0x00FF);
		if (sLen == 0x0081) {
			sLen = (short) (cmdbuf[sOff++]&0x00FF);
		}

		// cal PBOC PDOL Value Length
		sTmp = PBOCUtil.findValueOffByTag(TAG_PDOL, cmdbuf, sOff, sLen);
		short sPDOLValueLen;
		sPDOLValueLen = PBOCUtil.getValueLenByTLList(cmdbuf, sTmp, cmdbuf[(short)(sTmp-1)]);
		
		// contact fci
		if (dgi == DGI_PERSO_9102) {			
			contactfci = fci;
			paramBuf[PBOC_PARAM_OFF_PBOCPDOLVALUE_LEN] = (byte)sPDOLValueLen;			
			
			pbocpdol = new byte[cmdbuf[(short)(sTmp-1)]];
			Util.arrayCopy(cmdbuf, sTmp, pbocpdol, (short)0x00, (short)pbocpdol.length);
		} else {
			// contactless fci
			contactlessfci = fci;
			paramBuf[PBOC_PARAM_OFF_QPBOCPDOLVALUE_LEN] = (byte)sPDOLValueLen;			
			
			qpbocpdol = new byte[cmdbuf[(short)(sTmp-1)]];
			Util.arrayCopy(cmdbuf, sTmp, qpbocpdol, (short)0x00, (short)qpbocpdol.length);
		}			
		
		sOff = 0x01;
		sLen = (short)(fci[sOff++]&0x00FF);
		if (sLen == 0x81) {
			sLen = (short)(fci[sOff++]&0x00FF);
		}
				
		sOff = PBOCUtil.findValueOffByTag((short)0xA5, fci, sOff, sLen);		
		sLen = (short)(fci[(short)(sOff-0x01)]&0x00FF);
		
		sOff = PBOCUtil.findValueOffByTag((short)0xBF0C, fci, sOff, sLen);
		if (sOff != PBOCUtil.TAG_NOT_FOUND) {
			sLen = (short)(fci[(short)(sOff-0x01)]&0x00FF);
			
			sOff = PBOCUtil.findValueOffByTag(TAG_SECTION_PURCHASE_APP_ID, fci, sOff, sLen);
			// 0xDF61, 分段扣费应用标识
			if (sOff != PBOCUtil.TAG_NOT_FOUND) {
				sExtAppIndicateOff = sOff;				
			}
		}
	}
	
	/**
	 * perso GPO resposne data
	 * @param dgi		DGI of perso data.
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void persoGPO(short dgi, byte[] cmdbuf, short sOff, short sLen) {
		short sTmp = 0x00;
		short sValueOff;		
				
		// GPO response (PBOC)
		if (dgi == DGI_PERSO_9104) {			
			pbocGPO = new byte[(short)(sLen-0x04)];
			// copy AIP
			Util.arrayCopy(cmdbuf, (short)(sOff+0x02), pbocGPO, (short)0x00, (short)0x02);
			// copy AFL
			Util.arrayCopy(cmdbuf, (short)(sOff+0x06), pbocGPO, (short)0x02, (short)(pbocGPO.length-0x02));
		} else if (dgi == DGI_PERSO_9203) {
			// GPO response (EC)
			ecGPO = new byte[(short)(sLen-0x04)];
			// copy AIP
			Util.arrayCopy(cmdbuf, (short)(sOff+0x02), ecGPO, (short)0x00, (short)0x02);
			// copy AFL
			Util.arrayCopy(cmdbuf, (short)(sOff+0x06), ecGPO, (short)0x02, (short)(ecGPO.length-0x02));
		} else if (dgi == DGI_PERSO_9206) {
			// MSD is not exist in PBOC 3.0
		} else if (dgi == DGI_PERSO_9207) {
			qpbocGPO = new byte[(short)(cmdbuf[(short)(sOff+0x05)]+0x06)];
			Util.arrayCopy(cmdbuf, sOff, qpbocGPO, (short) 0x00, (short)qpbocGPO.length);
			
			// GPO response (QPBOC)
			// get qPBOC AIP
			sValueOff = PBOCUtil.findValueOffByTag(TAG_AIP, cmdbuf, sOff, sLen);
			Util.arrayCopy(cmdbuf, sValueOff, paramBuf, PBOC_PARAM_OFF_QPBOC_AIP, (short)0x02);
			
			// get last record sfi and record no
			sValueOff = PBOCUtil.findValueOffByTag(TAG_AFL, cmdbuf, sOff, sLen);
			sValueOff += (short) (cmdbuf[(short) (sValueOff-1)] - 4);
			sQPBOCLastRecDGI = Util.makeShort((byte)(cmdbuf[sValueOff]>>3), cmdbuf[(short)(sValueOff+2)]);

			// if qPBOC exist 9F10
			sValueOff = PBOCUtil.findValueOffByTag(TAG_ISSUE_APP_DATA, cmdbuf, sOff, sLen);
			if (sValueOff != PBOCUtil.TAG_NOT_FOUND) {
				sValueOff--;
				// qPBOC GPO Data take off 9F10
				sLen -= cmdbuf[sValueOff];
				if (cmdbuf[sValueOff] > 0x007F) {
					sLen -= 4;
				} else {
					sLen -= 3;
				}
				
				sTmp = (short) (cmdbuf[(short)(sValueOff+1)]+1);
				short sIssueAppData = (short)(cmdbuf[sValueOff]&0x0FF);
				// if exist QPBOC Issue Application data
				if (sIssueAppData > sTmp) {
					sIssueAppData = (byte) (sTmp + cmdbuf[(short)(sValueOff+1+sTmp)] + 1);
				}
				
				sQPBOCIssueAppDataLen = sIssueAppData;				
				Util.arrayCopy(cmdbuf, (short) (sValueOff+1), qpbocIssueAppData, (short)0x00, (short)(cmdbuf[sValueOff]&0x0FF));
			}
		}
	}
	
	/**
	 * create QPBOC ARQC/AAC GPO response template
	 * @param tmpBuf 	temp buffer, used cache data
	 */
	private void buildQPBOCARQCAACGPORsp(byte[] tmpBuf) {
		short sOff;
		
		tmpBuf[0x00] = 0x77;		
		// append AIP
		sOff = Util.arrayCopy(qpbocGPO, (short) 0x00, tmpBuf, (short) 0x03, (short) 0x04);
		
		// append ATC
		sOff = PBOCUtil.appendTLV(TAG_ATC, (short) 0x00, tmpBuf, sOff);
		sQPBOCARQCAACRspATCOff = (short)(sOff-2);
		
		// append 2ND track Data
		sOff = PBOCUtil.appendTLV(TAG_2ND_TRACK_DATA, cardDataBuf, (short) (CARD_DATA_OFF_2ND_TRACK_DATA+1), cardDataBuf[CARD_DATA_OFF_2ND_TRACK_DATA], tmpBuf, sOff);
		
		// append Issue application Data
		sOff = PBOCUtil.appendTLV(TAG_ISSUE_APP_DATA, qpbocIssueAppData, (short)0x00, sQPBOCIssueAppDataLen, tmpBuf, sOff);
		sQPBOCARQCAACRspIssueAPPOff = (short)(sOff-sQPBOCIssueAppDataLen);
		
		// append AC
		sOff = Util.setShort(tmpBuf, sOff, TAG_AC);
		tmpBuf[sOff++] = 0x08;
		sOff = Util.arrayFillNonAtomic(tmpBuf, sOff, (short) 0x08, (byte) 0x00);
		sQPBOCARQCAACRspACOff = (short)(sOff-0x08);
		
		// append 产品标识信息
		sOff = PBOCUtil.appendTLV(TAG_PRODUCET_ID_INFO, cardDataBuf, CARD_DATA_OFF_PRODUCET_ID_INFO, (short)0x10, tmpBuf, sOff);
		
		// append 应用PAN序列号
		sOff = PBOCUtil.appendTLV(TAG_APP_PAN_SEQUENCE_NO, cardDataBuf, CARD_DATA_OFF_PAN, (short) 0x01, tmpBuf, sOff);
		
		// append 卡片交易属性
		sOff = PBOCUtil.appendTLV(TAG_CARD_TRADE_ATTRIBUTE, cardDataBuf, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, (short)0x02, tmpBuf, sOff);
		sQPBOCARQCAACRspCardAttrOff = (short)(sOff-0x02);
		
		// append 可用脱机消费金额
		if (isCPPReturnAvailableMoney) {
			sOff = PBOCUtil.appendTLV(TAG_AVAILABLE_OFFLINE_MONEY, cardDataBuf, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06, tmpBuf, sOff);			
			sQPBOCARQCAACRspAvailMoneyOff = (byte) (sOff - 0x06);
		} else {
			sQPBOCARQCAACRspAvailMoneyOff = INVALID_VALUE;
		}
		
		// append 持卡人姓名
		sOff = PBOCUtil.appendTLV(TAG_CARD_HOLDER_NAME, cardDataBuf, (short) (CARD_DATA_OFF_CARD_HOLDER_NAME+1), cardDataBuf[CARD_DATA_OFF_CARD_HOLDER_NAME], tmpBuf, sOff);
		short sLen = (short) (sOff - 3);
		if (sLen > 0x7F) {
			tmpBuf[0x01] = (byte) 0x81;
			tmpBuf[0x02] = (byte) sLen;
		} else {
			tmpBuf[0x01] = (byte) sLen;
			Util.arrayCopy(tmpBuf, (short) 0x03, tmpBuf, (short) 0x02, sLen);
			sOff--;
			
			// modify offset
			sQPBOCARQCAACRspATCOff--;
			sQPBOCARQCAACRspIssueAPPOff--;
			sQPBOCARQCAACRspACOff--;
			sQPBOCARQCAACRspCardAttrOff--;
			if (sQPBOCARQCAACRspAvailMoneyOff != INVALID_VALUE) {
				sQPBOCARQCAACRspAvailMoneyOff--;
			}
		}
		
		byte[] gpoRsp = new byte[sOff];
		Util.arrayCopy(tmpBuf, (short) 0x00, gpoRsp, (short) 0x00, sOff);
				
		qpbocARQCACCGPORsp = gpoRsp;
	}
	
	/**
	 * get RSA Key Length
	 * @return RSA Key Length
	 */
	private short getRSAKeyLen() {			
		if (priCRTKey == null) {
			return 0x00;
		}
		
		return (short)(priCRTKey.getSize() / 0x08);
	}
	
	/**
	 * create QPBOC TC GPO response template
	 * @param tmpBuf 	temp buffer, used cache data
	 */
	private void buildQPBOCTCGOBRsp(byte[] tmpBuf) {
		short sOff;		
		
		tmpBuf[0x00] = 0x77;
		// append AIP and AFL
		sOff = Util.arrayCopy(qpbocGPO, (short) 0x00, tmpBuf, (short) 0x03, (short)qpbocGPO.length);
		
		// append ATC
		sOff = PBOCUtil.appendTLV(TAG_ATC, (short) 0x00, tmpBuf, sOff);
		sQPBOCTCRspATCOff = (short)(sOff-2);
		
		// append AC
		sOff = Util.setShort(tmpBuf, sOff, TAG_AC);
		tmpBuf[sOff++] = 0x08;
		sOff = Util.arrayFillNonAtomic(tmpBuf, sOff, (short) 0x08, (byte) 0x00);
		sQPBOCTCRspACOff = (short)(sOff-0x08);
		
		// append Issue application Data
		sOff = PBOCUtil.appendTLV(TAG_ISSUE_APP_DATA, qpbocIssueAppData, (short)0x00, sQPBOCIssueAppDataLen, tmpBuf, sOff);
		sQPBOCTCRspIssueAppOff = (short)(sOff-sQPBOCIssueAppDataLen);
		
		// append 2ND track Data
		sOff = PBOCUtil.appendTLV(TAG_2ND_TRACK_DATA, cardDataBuf, (short) (CARD_DATA_OFF_2ND_TRACK_DATA+1), cardDataBuf[CARD_DATA_OFF_2ND_TRACK_DATA], tmpBuf, sOff);
		
		// append 应用PAN序列号
		sOff = PBOCUtil.appendTLV(TAG_APP_PAN_SEQUENCE_NO, cardDataBuf, CARD_DATA_OFF_PAN, (short)0x01, tmpBuf, sOff);
		
		// append 签名的动态应用数据
		short sRSAKeyLen = getRSAKeyLen();
		if (PBOCUtil.isBitSet(tmpBuf, (short) 0x05, (short) 0x02) && (sRSAKeyLen>0x00) && (sRSAKeyLen<=0x80)) {
			// DDA长度超过1024 bit，签名数据通过读记录方式返回, 否则在GPO Response中返回
			sOff = Util.setShort(tmpBuf, sOff, TAG_SIGN_DYNAMIC_APP_DATA);
			if (sRSAKeyLen > 0x7F) {
				tmpBuf[sOff++] = (byte) 0x81;
			}
			tmpBuf[sOff++] = (byte) sRSAKeyLen;
			sOff = Util.arrayFillNonAtomic(tmpBuf, sOff, sRSAKeyLen, (byte) 0x00);
			sQPBOCTCRspICCSIGOff = (short)(sOff-sRSAKeyLen);
		}
		
		// append 卡片交易属性
		sOff = PBOCUtil.appendTLV(TAG_CARD_TRADE_ATTRIBUTE, cardDataBuf, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, (short)0x02, tmpBuf, sOff);
		sQPBOCTCRspCardAttrOff = (short)(sOff-0x02);
		
		// append 可用脱机消费金额
		if (isCPPReturnAvailableMoney) {
			// 1. qPBOC not support DDA
			// 2. if qPBOC support DDA and RSA Length <= 1024 bit
			// 满足上面2个条件之一，即需要在GPO响应中返回9F5D
			if ((!PBOCUtil.isBitSet(tmpBuf, (short) 0x05, (short) 0x02))
				|| (sRSAKeyLen<=0x80)) {
				sOff = PBOCUtil.appendTLV(TAG_AVAILABLE_OFFLINE_MONEY, cardDataBuf, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06, tmpBuf, sOff);			
				sQPBOCTCRspAvailMoneyOff = (short)(sOff - 0x06);	
			}
		}
		
		sRSAKeyLen = (short) (sOff - 3);
		if (sRSAKeyLen > 0x7F) {
			tmpBuf[0x01] = (byte) 0x81;
			tmpBuf[0x02] = (byte) sRSAKeyLen;
		} else {
			tmpBuf[0x01] = (byte) sRSAKeyLen;
			Util.arrayCopy(tmpBuf, (short) 0x03, tmpBuf, (short) 0x02, sRSAKeyLen);
			sOff--;
			
			// modify offset
			sQPBOCTCRspATCOff--;
			sQPBOCTCRspACOff--;
			sQPBOCTCRspIssueAppOff--;
			if (sQPBOCTCRspICCSIGOff != INVALID_VALUE) {
				sQPBOCTCRspICCSIGOff--;
			}
			sQPBOCTCRspCardAttrOff--;
			if (sQPBOCTCRspAvailMoneyOff != INVALID_VALUE) {
				sQPBOCTCRspAvailMoneyOff--;
			}
		}
		
		byte[] gpoRsp = new byte[sOff];
		Util.arrayCopy(tmpBuf, (short) 0x00, gpoRsp, (short) 0x00, sOff);
		
		qpbocTCGPORsp = gpoRsp;
	}
	
	/**
	 * create QPBOC GPO response template
	 * @param tmpBuf 	temp buffer, used cache data
	 */
	private void buildQPBOCGPORspTemplate(byte[] tmpBuf) {
		
		if (qpbocGPO == null) {
			return;
		}
		
		buildQPBOCARQCAACGPORsp(tmpBuf);
		
		short sSignatureLen = getRSAKeyLen();
		if ((sSignatureLen > 0x80)
			&& (sQPBOCSigDGI == 0x00)) {
			// create 0601 record
			byte index = getFreeRecTableIndex();
			// not enough record table space
			if (index == INVALID_RECORD_OBJECT_INDEX) {
				ISOException.throwIt(ISO7816.SW_FILE_FULL);
			}			
						
			short sRecordLen = (short) (sSignatureLen+4+3+6+3);
			byte[] record = new byte[sRecordLen];
			short sRecOff = 0x00;
			record[sRecOff++] = 0x70;
			record[sRecOff++] = (byte) 0x81;
			record[sRecOff++] = (byte)(sRecordLen-0x03);
			sRecOff = Util.setShort(record, sRecOff, TAG_SIGN_DYNAMIC_APP_DATA);
			record[sRecOff++] = (byte) 0x81;
			record[sRecOff++] = (byte) sSignatureLen;
			sRecOff += sSignatureLen;
			
			sRecOff = Util.setShort(record, sRecOff, TAG_AVAILABLE_OFFLINE_MONEY);
			record[sRecOff] = 0x06;
			
			recordObj[index] = record;
			recordMap[index] = (short)0x0601;	
			
			sQPBOCSigDGI = (short)0x0601;
			sQPBOCSigOff = 0x07;					
			
			sQPBOC9F5DDGI = (short)0x0601;
			sQPBOC9F5DOff = (short)(sRecordLen-0x06);
		}
		
		
		buildQPBOCTCGOBRsp(tmpBuf);
	}	
	
	/**
	 * create GPO response template
	 * @param tmpBuf 	temp buffer, used cache data
	 */
	private void buildGPORspTemplate(byte[] tmpBuf) {
		buildQPBOCGPORspTemplate(tmpBuf);
	}
	
	/**
	 * create DDA template 
	 * @param tmpBuf	temp buffer, used cache data
	 */
	private void buildDDATemplate(byte[] tmpBuf) {
		short sModuleLen = getRSAKeyLen();
		if (sModuleLen == 0x00) {
			return;
		}
		
		Util.arrayFillNonAtomic(tmpBuf, (short)0x00, sModuleLen, (byte)0x00);
		
		tmpBuf[DDA_OFF_HEADER] = 0x6A;
		tmpBuf[DDA_OFF_SIGN_FORMAT] = 0x05;
		tmpBuf[DDA_OFF_HASH_IDENTIFIER] = 0x01;
		tmpBuf[DDA_OFF_IC_DATA_LEN] = 0x03;
		tmpBuf[DDA_OFF_IC_DATA_DIGIT_LEN] = 0x02;
		
		short sPaddingLen = (short)(sModuleLen-28);
		Util.arrayFillNonAtomic(tmpBuf, DDA_OFF_PADDING_BB, sPaddingLen, (byte)0xBB);
		
		tmpBuf[(short)(sModuleLen-0x01)] = (byte) 0xBC;
		
		ddaTemplate = new byte[sModuleLen];
		Util.arrayCopy(tmpBuf, (short)0x00, ddaTemplate, (short)0x00, sModuleLen);
	}
			
	/**
	 * get log entry from fci
	 * @param fci PBOC/QPBOC FCI
	 * @param tag TAG_LOG_ENTRY/TAG_CHARGE_LOG_ENTRY
	 * @return log entry sfi + record number
	 */
	private short getLogEntry(byte[] fci, short tag) {
		if (fci == null) {
			return INVALID_VALUE;
		}
		
		short sOff = 0x01;
		short sLen = (short)(fci[sOff++]&0x00FF);
		if (sLen == 0x81) {
			sLen = (short)(fci[sOff++]&0x00FF);
		}
				
		sOff = PBOCUtil.findValueOffByTag((short)0xA5, fci, sOff, sLen);		
		sLen = (short)(fci[(short)(sOff-0x01)]&0x00FF);
		
		sOff = PBOCUtil.findValueOffByTag(TAG_FCI_ISUSSER_DATA, fci, sOff, sLen);
		if (sOff != PBOCUtil.TAG_NOT_FOUND) {
			sLen = (short)(fci[(short)(sOff-0x01)]&0x00FF);
			sOff = PBOCUtil.findValueOffByTag(tag, fci, sOff, sLen);
			if (sOff != PBOCUtil.TAG_NOT_FOUND) {
				return Util.makeShort(fci[sOff], fci[(short)(sOff+1)]);
			}
		}
		
		return INVALID_VALUE;
	}
	
	/**
	 * create log file
	 */
	private void createLogFile() {
		short sTmp;
		short sLen;
		short logEntry = getLogEntry(contactfci, TAG_LOG_ENTRY);
		if (logEntry == INVALID_VALUE) {
			logEntry = getLogEntry(contactlessfci, TAG_LOG_ENTRY);
		}
		
		if ((logFormat != null) && (logEntry != INVALID_VALUE)) {
			sTmp = (short) (logEntry&0x00FF);
			sLen = PBOCUtil.getValueLenByTLList(logFormat, (short)0x00, (short)logFormat.length);
			// 4 byte record counter
			sLen += 0x04;
			sTmp *= sLen;
			tradeLogFile = new byte[(short)(sTmp+LOG_INFO_OFF_CONTENT)];
			tradeLogFile[LOG_INFO_OFF_SFI] = (byte) ((logEntry>>0x08)&0x00FF);
			Util.setShort(tradeLogFile, LOG_INFO_OFF_RECLEN, sLen);
			tradeLogFile[LOG_INFO_OFF_RECNUM] = (byte) (logEntry&0x00FF);
		}
		
		logEntry = getLogEntry(contactfci, TAG_CHARGE_LOG_ENTRY);
		if (logEntry == INVALID_VALUE) {
			logEntry = getLogEntry(contactlessfci, TAG_CHARGE_LOG_ENTRY);
		}
		
		// create charge log file
		if ((chargelogFormat != null) && (logEntry != 0x00)) {
			sTmp = (short) (logEntry&0x00FF);
			sLen = PBOCUtil.getValueLenByTLList(chargelogFormat, (short)0x00, (short)chargelogFormat.length);
			// 4 byte record counter + 9F79/DF79 tag value 2 byte + before value 6 byte + after value 6 byte
			sLen += 18;
			sTmp *= sLen;
			chargeLogFile = new byte[(short)(sTmp+LOG_INFO_OFF_CONTENT)];
			chargeLogFile[LOG_INFO_OFF_SFI] = (byte) ((logEntry>>0x08)&0x00FF);				
			Util.setShort(chargeLogFile, LOG_INFO_OFF_RECLEN, sLen);
			chargeLogFile[LOG_INFO_OFF_RECNUM] = (byte) (logEntry&0x00FF);								
		}
	}
	
	/**
	 * build log template
	 */
	private void bulidLogTemplate() {
		if (tradeLogFile == null) {
			return;
		}
		
		short sLogFormatLen = (short) logFormat.length;		
		short tagItems = 0x00;
		short sLogFormatOff = 0x00;
		
		while (sLogFormatOff < sLogFormatLen) {
			// get tag
			short sTag = (short)(logFormat[sLogFormatOff++]&0x0FF);
			if (((short)(sTag&0x001F)) == ((short)0x001F)) {
				sTag <<= 8;
				sTag |= (short)(logFormat[sLogFormatOff++]&0x00FF);
			}
			
			// skip length byte
			sLogFormatOff++;
			
			tagItems++;
		}
		
		short sCDOL1Len = 0x00;
		short sCDOL2Len = 0x00;
		short sPDOLLen = 0x00;
		short sQPDOLLen = 0x00;
		
		boolean bPBOC = false;
		// perso PBOC Data
		if ((cdol1 != null) && (cdol2 != null) && (pbocpdol != null)) {
			bPBOC = true;
			sCDOL1Len = (short)cdol1.length;
			sCDOL2Len = (short)cdol2.length;
			sPDOLLen = (short)pbocpdol.length;
			
			logTemplate_1 = new short[(short)(tagItems*0x03)];
			logTemplate_2 = new short[(short)(tagItems*0x03)];
			
			if (qpbocpdol != null) {
				logTemplate_3 = new short[(short)(tagItems*0x03)];
				logTemplate_4 = new short[(short)(tagItems*0x03)];				
			}
		}

		boolean bQPBOC = false;
		// perso qPBOC data
		if (qpbocpdol != null) {
			bQPBOC = true;
			sQPDOLLen = (short)qpbocpdol.length;
			
			logTemplate_5 = new short[(short)(tagItems*0x03)];
		}		
		
		sLogFormatOff = 0x00;
				
		short sLogValueOff = 0x00;
		while (sLogFormatOff < sLogFormatLen) {
			// get tag
			short sTag = (short)(logFormat[sLogFormatOff++]&0x0FF);
			if (((short)(sTag&0x001F)) == ((short)0x001F)) {
				sTag <<= 8;
				sTag |= (short)(logFormat[sLogFormatOff++]&0x00FF);
			}
			
			short sValueLen = (short) (logFormat[sLogFormatOff++]&0x0FF);
			
			if (bPBOC) {
				// find in CDOL1
				short sOff = PBOCUtil.findValuePosInTLList(sTag, cdol1, (short)0x00, sCDOL1Len);
				if (sOff != PBOCUtil.TAG_NOT_FOUND) {
					logTemplate_1[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CDOL1;
					logTemplate_1[(short)(sLogValueOff+0x01)] = sOff;
					logTemplate_1[(short)(sLogValueOff+0x02)] = sValueLen;
					
					logTemplate_2[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CDOL1;
					logTemplate_2[(short)(sLogValueOff+0x01)] = sOff;
					logTemplate_2[(short)(sLogValueOff+0x02)] = sValueLen;
					
					if (bQPBOC) {
						logTemplate_3[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CDOL1;
						logTemplate_3[(short)(sLogValueOff+0x01)] = sOff;
						logTemplate_3[(short)(sLogValueOff+0x02)] = sValueLen;
						
						logTemplate_4[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CDOL1;
						logTemplate_4[(short)(sLogValueOff+0x01)] = sOff;
						logTemplate_4[(short)(sLogValueOff+0x02)] = sValueLen;
					}
				} else {
					// if not find in CDOL1, then find in CDOL2
					boolean bFind = true;
					sOff = PBOCUtil.findValuePosInTLList(sTag, cdol2, (short)0x00, sCDOL2Len);
					if (sOff != PBOCUtil.TAG_NOT_FOUND) {
						logTemplate_2[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CDOL2;
						logTemplate_2[(short)(sLogValueOff+0x01)] = sOff;
						logTemplate_2[(short)(sLogValueOff+0x02)] = sValueLen;
						
						if (bQPBOC) {
							logTemplate_4[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CDOL2;
							logTemplate_4[(short)(sLogValueOff+0x01)] = sOff;
							logTemplate_4[(short)(sLogValueOff+0x02)] = sValueLen;						
						}
						
						bFind = false;
					}
					
					// if not find in CDOL1/CDOL2, then find in PDOL
					sOff = PBOCUtil.findValuePosInTLList(sTag, pbocpdol, (short)0x00, sPDOLLen);
					if (sOff != PBOCUtil.TAG_NOT_FOUND) {
						logTemplate_1[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_PDOL;
						logTemplate_1[(short)(sLogValueOff+0x01)] = sOff;
						logTemplate_1[(short)(sLogValueOff+0x02)] = sValueLen;
						
						if (bFind) {
							logTemplate_2[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_PDOL;
							logTemplate_2[(short)(sLogValueOff+0x01)] = sOff;
							logTemplate_2[(short)(sLogValueOff+0x02)] = sValueLen;
						}
					} else {
						// if not find in PDOL, then find in card data
						short index = findTagInAnalyseTable(sTag);
						if (index == INVALID_VALUE) {
							logTemplate_1[(short)(sLogValueOff+0x00)] = INVALID_VALUE;
							logTemplate_1[(short)(sLogValueOff+0x01)] = INVALID_VALUE;
							logTemplate_1[(short)(sLogValueOff+0x02)] = sValueLen;
							
							if (bFind) {
								logTemplate_2[(short)(sLogValueOff+0x00)] = INVALID_VALUE;
								logTemplate_2[(short)(sLogValueOff+0x01)] = INVALID_VALUE;
								logTemplate_2[(short)(sLogValueOff+0x02)] = sValueLen;
							}
						} else {
							logTemplate_1[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CARD;
							logTemplate_1[(short)(sLogValueOff+0x01)] = analyseTable[(short)(index+ANALYSE_TABLE_OFF_VALUE_OFF)];
							logTemplate_1[(short)(sLogValueOff+0x02)] = sValueLen;
							
							if (bFind) {
								logTemplate_2[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CARD;
								logTemplate_2[(short)(sLogValueOff+0x01)] = analyseTable[(short)(index+ANALYSE_TABLE_OFF_VALUE_OFF)];
								logTemplate_2[(short)(sLogValueOff+0x02)] = sValueLen;
							}
						}
					}
					
					if (bQPBOC) {
						sOff = PBOCUtil.findValuePosInTLList(sTag, qpbocpdol, (short)0x00, sQPDOLLen);
						if (sOff != PBOCUtil.TAG_NOT_FOUND) {
							logTemplate_3[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_PDOL;
							logTemplate_3[(short)(sLogValueOff+0x01)] = sOff;
							logTemplate_3[(short)(sLogValueOff+0x02)] = sValueLen;
							
							if (bFind) {
								logTemplate_4[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_PDOL;
								logTemplate_4[(short)(sLogValueOff+0x01)] = sOff;
								logTemplate_4[(short)(sLogValueOff+0x02)] = sValueLen;
							}
						} else {
							// if not find in PDOL, then find in card data
							short index = findTagInAnalyseTable(sTag);
							if (index == INVALID_VALUE) {
								logTemplate_3[(short)(sLogValueOff+0x00)] = INVALID_VALUE;
								logTemplate_3[(short)(sLogValueOff+0x01)] = INVALID_VALUE;
								logTemplate_3[(short)(sLogValueOff+0x02)] = sValueLen;
								
								if (bFind) {
									logTemplate_4[(short)(sLogValueOff+0x00)] = INVALID_VALUE;
									logTemplate_4[(short)(sLogValueOff+0x01)] = INVALID_VALUE;
									logTemplate_4[(short)(sLogValueOff+0x02)] = sValueLen;
								}
							} else {
								logTemplate_3[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CARD;
								logTemplate_3[(short)(sLogValueOff+0x01)] = analyseTable[(short)(index+ANALYSE_TABLE_OFF_VALUE_OFF)];
								logTemplate_3[(short)(sLogValueOff+0x02)] = sValueLen;
								
								if (bFind) {
									logTemplate_4[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CARD;
									logTemplate_4[(short)(sLogValueOff+0x01)] = analyseTable[(short)(index+ANALYSE_TABLE_OFF_VALUE_OFF)];
									logTemplate_4[(short)(sLogValueOff+0x02)] = sValueLen;
								}
							}
						}
					}
				}				
			}
			
			if (bQPBOC) {
				short sOff = PBOCUtil.findValuePosInTLList(sTag, qpbocpdol, (short)0x00, sQPDOLLen);
				if (sOff != PBOCUtil.TAG_NOT_FOUND) {
					logTemplate_5[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_PDOL;
					logTemplate_5[(short)(sLogValueOff+0x01)] = sOff;
					logTemplate_5[(short)(sLogValueOff+0x02)] = sValueLen;
				} else {
					// if not find in PDOL, then find in card data
					short index = findTagInAnalyseTable(sTag);
					if (index == INVALID_VALUE) {
						logTemplate_5[(short)(sLogValueOff+0x00)] = INVALID_VALUE;
						logTemplate_5[(short)(sLogValueOff+0x01)] = INVALID_VALUE;
						logTemplate_5[(short)(sLogValueOff+0x02)] = sValueLen;
					} else {
						logTemplate_5[(short)(sLogValueOff+0x00)] = LOG_VALUE_TYPE_CARD;
						logTemplate_5[(short)(sLogValueOff+0x01)] = analyseTable[(short)(index+ANALYSE_TABLE_OFF_VALUE_OFF)];
						logTemplate_5[(short)(sLogValueOff+0x02)] = sValueLen;
					}
				}
			}
			
			sLogValueOff += 0x03;
		}
	}
	
	/**
	 * init application conditions
	 */
	private void appInit() {
		isCPPSupportECCheck = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_SUPPORT_EC_CHECK);
		isCPPSupportECAndCTTACheck = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_SUPPORT_EC_AND_CTTA_CHECK);		
		isCPPSupportECOrCTTACheck = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_SUPPORT_EC_OR_CTTA_CHECK);
		isCPPSupportNewCardCheck = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_SUPPORT_NEW_CARD_CHECK);
		isCPPSupportPINCheck = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_SUPPORT_PIN_CHECK);
		isCPPAllowCoinNotMatchOffline = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_ALLOW_COIN_NOT_MATCH_OFFLINE);		
		isCPPFstContactPBOCOnline = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_FST_CONTACT_PBOC_ONLINE);		
		isCPPReturnAvailableMoney = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_RETURN_AVAILABLE_MONEY);		
		isCPPSupportPrePay = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_PRE_PAY);		
		isCPPNotAllowCoinNotMatchTrade = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_NOT_ALLOW_COIN_NOT_MATCH_TRADE);
		isCPPNewCardOnlySupportOffline = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_NEWCARD_ONLY_SUPPORT_OFFLINE);
		isCPPQPBOCSupportTradeLog = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_QPBOC_SUPPORT_LOG);
		isCPPMatchCoinTradeSupportPIN = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_MATCH_COIN_TRADE_SUPPORT_PIN);
		isCPPNotMatchCoinTradeSupportPIN = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_NOT_MATCH_COIN_TRADE_SUPPORT_PIN);
		isCPPNotMatchCoinTradeReqCVM = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_NOT_MATCH_COIN_TRADE_REQUEST_CVM);
		isCPPSupportSign = PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_CARD_PLUS_PROCESS, CPP_SUPPORT_SIGN);
		
		bCTTAULNotExist = PBOCUtil.isAllZero(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, (short)0x06);
		bIsQPBOCSupportDDA = PBOCUtil.isBitSet(qpbocGPO, (short)0x02, AIP_SUPPORT_OFF_DDA);
		
		short pdolValueLen = (short)(paramBuf[PBOC_PARAM_OFF_PBOCPDOLVALUE_LEN]&0x0FF);
		short tmp = (short)(paramBuf[PBOC_PARAM_OFF_QPBOCPDOLVALUE_LEN]&0x0FF);
		if (pdolValueLen < tmp) {
			pdolValueLen = tmp;
		}
		if (FUNCTION_FOR_TIANYU) {
			pdolValue = JCSystem.makeTransientByteArray(pdolValueLen, JCSystem.CLEAR_ON_RESET);
		} else {
			pdolValue = JCSystem.makeTransientByteArray(pdolValueLen, JCSystem.CLEAR_ON_DESELECT);
		}

		if (sQPBOCIssueAppDataLen == 0x00) {
			sQPBOCIssueAppDataLen = (short)pbocIssueAppData.length;
			Util.arrayCopy(pbocIssueAppData, (short)0x00, qpbocIssueAppData, (short)0x00, sQPBOCIssueAppDataLen);			
		}
		
		// get terminal data offset in pdol value offset
		getTerminalDataOffInPODLValue();
		// get terminal data offset in CDOL1/CDOL2 value offset
		getTerminalDataOffInCDOLValue();
		
		short index;
		for (index=0x00; index<RECORD_OBJECT_SIZE; index++) {					
			if (sQPBOCLastRecDGI == recordMap[index]) {
				break;
			}
		}
		
		if (index < RECORD_OBJECT_SIZE) {
			byte[] rec = (byte[])recordObj[index];
			short sOff = 0x01;
			short sLen = (short)(rec[sOff++]&0x0FF);
			if (sLen == 0x81) {
				sLen = (short)(rec[sOff++]&0x0FF);
			}
			
			short sValueOff = PBOCUtil.findValueOffByTag(TAG_CARD_AUTH_DATA, rec, sOff, sLen);
			if (sValueOff != PBOCUtil.TAG_NOT_FOUND) {
				sValueOff -= 0x03;
				
				sLen -= 0x0B;
				tmp = (short)(sLen > 0x7F ? 0x03 : 0x02);
				byte[] newRec = new byte[(short)(sLen+tmp)];			
				newRec[0x00] = 0x70;
				if (tmp == 0x02) {
					newRec[0x01] = (byte)sLen;
				} else {
					newRec[0x01] = (byte)0x81;
					newRec[0x02] = (byte)sLen;
				}
				
				tmp = Util.arrayCopy(rec, sOff, newRec, tmp, (short)(sValueOff-sOff));
				if ((short)(sValueOff+0x0B) < (short)rec.length) {
					Util.arrayCopy(rec, (short)(sValueOff+0x0B), newRec, tmp, (short)(rec.length - sValueOff - 0x0B));				
				}
				
				recordObj[index] = newRec;
				if (JCSystem.isObjectDeletionSupported()) {
					JCSystem.requestObjectDeletion();
				}			
			}			
		}	
	}
	
	/**
	 * find extend application file index by SFI
	 * @param sfi	extend application fil SFI
	 * @return	fild index
	 */
	private short findExtendFile(byte sfi) {
		short size = (short) extAppFiles.length;
		for (short i=0x00; i<size; i++) {
			byte[] file = (byte[])extAppFiles[i];
			if ((file != null) 
				&& (file[EXT_APP_FILE_OFF_SFI] == sfi)) {
				return i;
			}			
		}
		
		return INVALID_VALUE;
	}	
	
	/**
	 * perso extend application files
	 * @param sc		secure channel interface
	 * @param dgi		DGI of perso data
	 * @param cmdbuf	perso data buffer.
	 * @param sOff		perso data offset.
	 * @param sLen		perso data lenth.
	 */
	private void persoExtendFile(SecureChannel sc, short dgi, byte[] cmdbuf, short sOff, short sLen) {		
		short i = sOff;
		
		if (dgi == DGI_PERSO_A001) {				
			if (extAppFiles != null) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			
			if ((short)(sLen%0x07) != 0x00) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			short sItemSize = (short)(sLen / 0x07);
			
			extAppFiles = new Object[sItemSize];
			short index = 0x00;
						
			sLen += sOff;
			while (i<sLen) {
				byte sfi = cmdbuf[i++];
				byte fileType = cmdbuf[i++];
				short sFileSize;
				short sMaxRecLen;				
				
				i += 0x02;
				sMaxRecLen = (short) (cmdbuf[i++]&0x0FF);
				
				if (fileType == 0x02) {
					sFileSize = (short)((short)(cmdbuf[i]&0x0FF)*(short)(short)(cmdbuf[(short)(i+0x01)]&0x0FF));
				} else {
					sFileSize = Util.getShort(cmdbuf, i);
				}				
				i += 0x02;
				
				if (findExtendFile(sfi) != INVALID_VALUE) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				byte[] file = new byte[EXT_APP_FILE_HEADLEN_SIZE];
				
				file[EXT_APP_FILE_OFF_SFI] = sfi;
				file[EXT_APP_FILE_OFF_TYPE] = fileType;
				Util.setShort(file, EXT_APP_FILE_OFF_MAX_SIZE, sFileSize);					
				file[EXT_APP_FILE_OFF_MAX_RECLEN] = (byte) sMaxRecLen;
								
				extAppFiles[index++] = file;			
			}
						
			// item is 1 byte sfi + 2 byte ID + 6 byte pre-authorization money = 9 byte
			// 3 item = 3 * 9 = 27
			extendPreAuthContext = new byte[27];
		} else if (dgi == DGI_PERSO_8020) {
			if ((short)(sLen % 0x10) != 0x00) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			
			if (sc != null) {
				sc.decryptData(cmdbuf, sOff, sLen);
			}
						
			if (extAppFiles == null) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
						
			sLen += sOff;
			short index = 0x00;			
			while (i<sLen) {				
				Util.arrayCopy(cmdbuf, i, (byte[])extAppFiles[index++], EXT_APP_FILE_OFF_OPEN_KEY, (short)0x10);
				
				i += 0x10;
			}
		} else {
			if ((short)(sLen % 0x03) != 0x00) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
						
			if (extAppFiles == null) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
						
			sLen += sOff;
			short index = 0x00;	
			while (i<sLen) {
				Util.arrayFillNonAtomic(cmdbuf, (short) 0x00, (short) 0x08, (byte) 0x00);
				
				tripleDesKey.setKey((byte[])extAppFiles[index++], EXT_APP_FILE_OFF_OPEN_KEY);
				cipherECBEncrypt.doFinal(cmdbuf, (short) 0x00, (short) 0x08, cmdbuf, (short) 0x00);
				if (Util.arrayCompare(cmdbuf, (short) 0x00, cmdbuf, i, (short) 0x03) != 0x00) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				i += 0x03;
			}
		}
	}
	
	/**
	 * STORE-DATA Command route. no RAPDU.
	 * @param sc		SecureChannel.
	 * @param apduBuf	apdu buffer.
	 */
	private void onStoreData(SecureChannel sc, byte[] apduBuf) {		
		if (appState == APP_STATE_ISSUED) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		if (blockNum == 0x00) {
			Util.arrayFillNonAtomic(qpbocIssueAppData, (short)0x00, (short)qpbocIssueAppData.length, (byte)0x00);
		}
		
		if (blockNum != apduBuf[ISO7816.OFFSET_P2]) {
			blockNum = 0x00;
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		byte p1 = apduBuf[ISO7816.OFFSET_P1];
		short dgi;
		short sOff = ISO7816.OFFSET_CDATA;
		short sLen = (short) (apduBuf[ISO7816.OFFSET_LC]&0x00FF);
		short sTmp;
		byte sfi;
		if (persoDGI != 0x00) {
			dgi = persoDGI;
			sfi = (byte)(dgi >> 0x08);
		} else {			
			dgi = Util.getShort(apduBuf, ISO7816.OFFSET_CDATA);
			sfi = apduBuf[ISO7816.OFFSET_CDATA];
			sOff += 0x03;
			sLen -= 0x03;
		}
		
		JCSystem.beginTransaction();
		
		// 01-1E SFI(not incalude 0x0D, 0x0E)
		if ((sfi > 0x00) && (sfi < 0x1F)) {
			persoRecContent(dgi, apduBuf, sOff, sLen);
		} else {
			switch (dgi) {
			// DES key
			case DGI_PERSO_8000:
				sLen = sc.decryptData(apduBuf, sOff, (short) 0x30);
				if (sLen != 0x30) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				Util.arrayCopy(apduBuf, sOff, paramBuf, PBOC_PARAM_OFF_APP_KEY, (short) 0x30);
				break;
			// dCVN key
			case DGI_PERSO_8001:
				break;
			// offline PIN
			case DGI_PERSO_8010:
				sLen = sc.decryptData(apduBuf, sOff, (short) 0x08);
				if (sLen != 0x08) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				Util.arrayCopy(apduBuf, sOff, paramBuf, PBOC_PARAM_OFF_PIN_VALUE, (short) 0x06);			
				break;
			// RSA Key
			case DGI_PERSO_8201:
			case DGI_PERSO_8202:
			case DGI_PERSO_8203:
			case DGI_PERSO_8204:
			case DGI_PERSO_8205:
				sLen = sc.decryptData(apduBuf, sOff, sLen);
				while (apduBuf[(short)(sOff+sLen-1)] == (byte) 0x00) {
					sLen--;
				}
				
				if (apduBuf[(short)(sOff+sLen-1)] != (byte)0x80) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				sLen--;
				
				persoRSACRTKey(dgi, apduBuf, sOff, sLen);
				break;
			// DES Key Check Value
			case DGI_PERSO_9000:
				if (sLen != 0x09) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				Util.arrayFillNonAtomic(apduBuf, (short) 0x40, (short) 0x08, (byte) 0x00);
				
				tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_APP_KEY);								
				cipherECBEncrypt.doFinal(apduBuf, (short) 0x40, (short) 0x08, apduBuf, (short) 0x50);
				if (Util.arrayCompare(apduBuf, (short) 0x50, apduBuf, sOff, (short) 0x03) != 0x00) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_MAC_KEY);					
				cipherECBEncrypt.doFinal(apduBuf, (short) 0x40, (short) 0x08, apduBuf, (short) 0x50);
				if (Util.arrayCompare(apduBuf, (short) 0x50, apduBuf, (short) (sOff+0x03), (short) 0x03) != 0x00) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_DEK_KEY);				
				cipherECBEncrypt.doFinal(apduBuf, (short) 0x40, (short) 0x08, apduBuf, (short) 0x50);
				if (Util.arrayCompare(apduBuf, (short) 0x50, apduBuf, (short) (sOff+0x06), (short) 0x03) != 0x00) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}				
				break;
			// PIN Max Retry Counter
			case DGI_PERSO_9010:
				if (sLen != 0x02) {
					ISOException.throwIt(ISO7816.SW_WRONG_DATA);
				}
				
				Util.arrayCopy(apduBuf, sOff, paramBuf, PBOC_PARAM_OFF_PIN_LEFT_CNTR, (short) 0x02);
				break;
			// Select FCI(PBOC)
			case DGI_PERSO_9102:
			// Select FCI(qPBOC)
			case DGI_PERSO_9103:
				persoFCI(dgi, apduBuf, sOff, sLen);
				break;
			// GPO response (PBOC)
			case DGI_PERSO_9104:
			// GPO response (EC)
			case DGI_PERSO_9203:
			// GPO response (MSD)
			case DGI_PERSO_9206:
			// GPO response (QPBOC)
			case DGI_PERSO_9207:
				persoGPO(dgi, apduBuf, sOff, sLen);
				break;
			// PBOC Issue Application Data
			case DGI_PERSO_9200:
				// skip "9F10"
				sOff += 0x02;
				
				sTmp = (short) (apduBuf[(short)(sOff+1)]+1);
				short sIssueAppData = (short)(apduBuf[sOff]&0x0FF);
				if (sIssueAppData > sTmp) {
					sIssueAppData = (byte) (sTmp + apduBuf[(short)(sOff+1+sTmp)] + 1);
				}
								
				pbocIssueAppData = new byte[sIssueAppData];								
				Util.arrayCopy(apduBuf, (short) (sOff+1), pbocIssueAppData, (short)0x00, (short)(apduBuf[sOff]&0x0FF));				
				break;
			case DGI_PERSO_A001:
			case DGI_PERSO_8020:
			case DGI_PERSO_9020:
				persoExtendFile(sc, dgi, apduBuf, sOff, sLen);	
				break;
			default:
				ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
			}		
		}
		
		// end perso
		if ((byte)(p1&0x80) == (byte)0x80) {
			appState = APP_STATE_ISSUED;
			
			appInit();
			buildGPORspTemplate(apduBuf);
			buildDDATemplate(apduBuf);			
			createLogFile();
			bulidLogTemplate();						
						
			curPersoAppletNum++;
			if (curPersoAppletNum == maxAppletNum) {
				cardState[0] = CARD_STATE_ISSUED;
			}
			
			blockNum = 0x00;
		} else {
			blockNum++;
		}
		
		JCSystem.commitTransaction();
	}

	/**
	 * judge trade is ec trade
	 * @param bType	true is PBOC, false is QPBOC
	 * @return
	 */
	private boolean isECTrade(boolean bType) {		
		short sECSupportOff;
		short sTradeCoinOff;
		short sTradeMoneyOff;
		
		if (bType) {
			sECSupportOff = sPPDOLECTerSupportIndicateOff;
			sTradeCoinOff = sPPDOLTradeCoinCodeOff;
			sTradeMoneyOff = sPPDOLTradeAuthMoneyOff;
		} else {
			sECSupportOff = sQPDOLECTerSupportIndicateOff;
			sTradeCoinOff = sQPDOLTradeCoinCodeOff;
			sTradeMoneyOff = sQPDOLTradeAuthMoneyOff;
		}
		
		boolean bIsECSecond = false;
		
		// 2. 交易货币代码与应用货币代码匹配		
		if (sTradeCoinOff != INVALID_VALUE) {
			if (Util.arrayCompare(pdolValue, sTradeCoinOff, cardDataBuf, CARD_DATA_OFF_APPCOINCODE, (short)0x02) == 0x00) {
				bIsECSecond = false;
			} else if (Util.arrayCompare(pdolValue, sTradeCoinOff, cardDataBuf, CARD_DATA_OFF_EC_SECOND_APP_COIN_CODE, (short)0x02) == 0x00) {
				bIsECSecond = true;
			} else {
				return false;
			}
			curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE] = bIsECSecond;			
		}
		
		// 1. 命令中包含电子现金终端支持指示器（设置为1）		
		if ((sECSupportOff == INVALID_VALUE)
			|| (pdolValue[sECSupportOff] != 1)) {
			return false;
		}	

		// 3. 授权金额不超过电子现金余额
		if (PBOCUtil.arrayCompare(pdolValue, sTradeMoneyOff, abyCurTradeCardData, bIsECSecond ? CARD_DATA_OFF_EC_SECOND_BALANCE : CARD_DATA_OFF_EC_BALANCE, (short)0x06) == 1) {
			return false;
		}
		
		// 4. 授权金额不超过电子现金单笔交易限额
		if (PBOCUtil.arrayCompare(pdolValue, sTradeMoneyOff, cardDataBuf, bIsECSecond ? CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT : CARD_DATA_OFF_SINGLE_CARD_LIMIT, (short)0x06) == 1) {
			return false;
		}
		
		// 5. 发卡行认证失败指示器为0
		// 6. 上次联机交易发卡行脚本处理失败指示器为0
		if ((abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] != 0x00)
			|| (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] != 0x00)) {
			return false;
		}
				
		// 7. PIN尝试次数不为0
		if ((paramBuf[PBOC_PARAM_OFF_PIN_MAX_CNTR] != 0x00) 
			&& (paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] == 0x00)) {
			return false;
		}
		
		return true;
	}

	/**
	 * calculate 9F5D
	 */
	private void calAvailableMoney() {
		// 支持小额检查
		if (isCPPSupportECCheck) {
			// 可用脱机余额等于电子现金余额
			short sOff;
			if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE]) {
				sOff = CARD_DATA_OFF_EC_SECOND_BALANCE;
			} else {
				sOff = CARD_DATA_OFF_EC_BALANCE;
			}
			Util.arrayCopyNonAtomic(abyCurTradeCardData, sOff, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06);
		} else if (isCPPSupportECAndCTTACheck) {
			// 可用脱机余额等于CTTAUL/CTTAL - CTTA
			if (bCTTAULNotExist) {
				// CTTAUL不存在, 使用CTTAL
				PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
			} else {
				PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
			}
		} else if (isCPPSupportECOrCTTACheck) {
			// 可用脱机余额等于电子现金余额+(CTTAUL/CTTAL - CTTA)
			if (bCTTAULNotExist) {
				// CTTAUL不存在, 使用CTTAL
				PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
			} else {
				PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
			}
			
			PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
		} else {
			// 用0填充
			Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06, (byte)0x00);
		}
	}
	
	/**
	 * qpbo card risk manager
	 * @param tmpBuf			temp buffer
	 * @param bIsTradeCoinMatch	is trade coin match
	 * @param bIsECSecond		is secord coin ec trade
	 * @return
	 */
	private byte qPBOCCardRiskManager(byte[] tmpBuf, boolean bIsTradeCoinMatch, boolean bIsECSecond) {
				
		/**
		 * 1. 设置货币匹配或不匹配
		 * 货币被比较一次同时保存结果。进行如下处理：
		 * 如果使用的货币代码（标签“9F51”）等于交易货币代码（标签“5F2A”），将匹配货币位设置为‘1’
		 * 如果匹配货币位=‘0’而且不允许不匹配货币交易（卡片附加处理的第 2字节第 7 位=‘1’）拒绝交易。
		 */
		if (!bIsTradeCoinMatch && isCPPNotAllowCoinNotMatchTrade) {
			// 如果匹配货币位=‘0’而且不允许不匹配货币交易（卡片附加处理的第 2字节第 7 位=‘1’）拒绝交易。
			return TRADE_RESULT_AAC;
		}
		
		boolean bIsOnlySupportOffline = PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_ONLY_OFFLINE);
		
		short sCVMLimitOff;
		short sECBalanceOff;
		short sSingleCardLimitOff;
		short sECResetThresholdOff;
		if (bIsECSecond) {
			sCVMLimitOff = CARD_DATA_OFF_EC_SECOND_CVM_LIMIT;
			sECBalanceOff = CARD_DATA_OFF_EC_SECOND_BALANCE;
			sSingleCardLimitOff = CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT;
			sECResetThresholdOff = CARD_DATA_OFF_EC_SECOND_RESET_THRESHOLD;
		} else {
			sCVMLimitOff = CARD_DATA_OFF_CARD_CVM_LIMIT;
			sECBalanceOff = CARD_DATA_OFF_EC_BALANCE;
			sSingleCardLimitOff = CARD_DATA_OFF_SINGLE_CARD_LIMIT;
			sECResetThresholdOff = CARD_DATA_OFF_EC_RESET_THRESHOLD;
		}
		
		/**
		 * 2. 终端仅支持脱机
		 * 如果终端仅支持脱机，跳过联机请求检查
		 * 如果终端仅支持脱机（终端交易属性，第 1 字节第 4 位=‘1’），卡片需要尝试脱机处理
		 */
		if (bIsOnlySupportOffline) {
			// 将仅脱机终端位（内部卡指示器）设置为‘1’
			//abyCardInterIndicators[CARD_INTER_OFF_ONLY_OFFLINE] = CARD_INTER_ONLY_OFFLINE;
			
			// 如果上次联机 ATC 寄存器为 0，并且如果是新卡且终端仅支持脱机（卡片附加处理的第2 字节第 6 位=‘1’），就拒绝交易
			if ((Util.getShort(abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC) == 0x00)
				&& isCPPNewCardOnlySupportOffline) {
				return TRADE_RESULT_AAC;
			}
			
			// 脱机 PIN 尝试上限超过
			// 如果终端仅支持脱机且支持 PIN 尝试超过检查（卡片附加处理的第 1字节第 4 位），
			// 则当脱机PIN 尝试计数器（标签“9F17”）存在并等于 0（没有剩余的 PIN 尝试），卡片应当拒绝交易
			if (isCPPSupportPINCheck) {
				// 将 CVR 的第 3 字节第 7 位设置为‘1’（PIN尝试上限超过）
				if ((paramBuf[PBOC_PARAM_OFF_PIN_MAX_CNTR] != 0x00) && (paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] == 0x00)) {
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_BLOCKED);
					return TRADE_RESULT_AAC;
				}
			}
			
			// 如果终端仅支持脱机，并且下面有一种情况满足
			// 1. 在终端交易属性中终端要求 CVM（第 2 字节第 7 位=‘1’）
			// 2. 匹配货币位=‘1’，且授权金额大于卡片 CVM 限额
			// 3. 匹配货币位=‘0’，而对于不匹配货币交易卡片请求 CVM 位=‘1’（卡片附加处理的第 3 字节第 6 位）
			if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_REQ_CVM)
				|| (bIsTradeCoinMatch && (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, sCVMLimitOff, (short)0x06) == 1))
				|| (!bIsTradeCoinMatch && isCPPNotMatchCoinTradeReqCVM)) {
				// 如果在终端交易属性中支持签名（第1字节第2位＝‘1’），且卡片附加处理也支持签名（第3字节第5位＝‘1’），于是在卡片交易属性中设置需要签名并尝试脱机处理
				// 将卡片交易属性的第 1 字节第 7 位置为‘1’
				if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_SIGN)
					&& isCPPSupportSign) {
					PBOCUtil.setBit(abyCurTradeCardData, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, CARD_TRADE_ATTR_NEED_SIGN);
				} else {
					// 如果在终端交易属性中不支持签名（第1字节第2位＝‘0’），或卡片附加处理不支持签名（第3字节第5位＝‘0’），终止非接触交易。
					return TRADE_RESULT_ABORT;
				}				
			}
		} else {
			// 联机请求检查
			
			/**
			 * 3. 终端或卡请求 CVM
			 * 终端可以请求CVM（总是或者对超过终端CVM请求上限的交易）。卡同样也可以请求CVM。目前qPBOC支持两种方式验证持卡人：联机PIN和签名
			 * 如果卡或终端请求CVM，而卡不支持任何一种终端在终端交易属性中指明的CVM，则交易将被终止
			 * 如果请求CVM而且联机PIN同时被终端和卡所支持，则交易将通过联机来处理
			 * 如果请求CVM但没有被卡和终端同时支持的CVM，则交易被终止
			 */
			 
			// 1. 如果终端交易属性的 CVM 请求位（第 2 字节第 7 位）为‘1’
			// 2. 如果终端交易属性的 CVM 请求位（第 2 字节第 7 位）为‘0’,匹配货币位＝‘1’，同时授权金额大于卡片 CVM 限额
			// 3. 如果终端交易属性的 CVM 请求位（第 2 字节第 7 位）为‘0’,匹配货币位＝‘0’，且不匹配货币交易卡片请求 CVM 位=‘1’（卡片附加处理的第 3字节第 6 位）
			if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_REQ_CVM)
				|| (bIsTradeCoinMatch && (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, sCVMLimitOff, (short)0x06) == 1))
				|| (!bIsTradeCoinMatch && isCPPNotMatchCoinTradeReqCVM)) {
				
				// 如果在终端交易属性（第 1 字节第 3 位）中支持联机 PIN，同时下面任一情况满足
				// 1. 匹配货币位＝‘1’，同时对于匹配货币，联机 PIN 支持位=‘1’（卡片附加处理的第 3字节第 8 位）
				// 2. 匹配货币位＝‘0’，同时对于不匹配货币，联机 PIN 支持位=‘1’（卡片附加处理的第 3 字节第 7 位）
				// 表示卡和终端均支持联机 PIN
				if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_ONLINE_PIN)
					&& ((bIsTradeCoinMatch && isCPPMatchCoinTradeSupportPIN)
						|| (!bIsTradeCoinMatch && isCPPNotMatchCoinTradeSupportPIN))) {
					// 卡要将卡交易属性（标签“9F6C”，第 1 字节第 8 位）设置为‘1’，并请求联机处理
					PBOCUtil.setBit(abyCurTradeCardData, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, CARD_TRADE_ATTR_NEED_ONLINE_PIN);
					return TRADE_RESULT_ARQC;
				} else if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_SIGN)
							&& isCPPSupportSign) {
					// 如果终端交易属性（第 1 字节第2 位）支持签名同时卡片附加处理的签名支持位=‘1’（第 3字节第 5 位）：
					// 表示卡和终端均支持签名 
					// 将卡片交易属性的签名请求位设置为‘1’，然后继续卡片风险管理处理
					PBOCUtil.setBit(abyCurTradeCardData, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, CARD_TRADE_ATTR_NEED_SIGN);					
				} else {
					return TRADE_RESULT_ABORT;
				}				
			}

			/**
			 * 4. 检查联机处理请求
			 * 卡片和终端可以基于交易条件请求联机处理。如果先前的检查没有指示需要联机处理，或终止非接触交易，执行该检查决定是否存在其它的条件导致联机处理
			 */

			// 1. 如果终端请求联机处理（终端交易属性的第 2字节第 8 位＝‘1’），则卡也要请求联机处理
			// 2. 如果不允许不匹配货币的脱机交易（卡片附加处理的第 1字节第 3 位=‘0’）同时匹配货币位=‘0’
			// 则卡片应请求联机处理
			if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_REQ_ARQC)
				|| (!bIsTradeCoinMatch && (!isCPPAllowCoinNotMatchOffline))) {
				return TRADE_RESULT_ARQC;
			}
			
			// 如果支持新卡检查（卡片附加处理的第 1 字节第5 位= ‘1’ ）同时上次联机 ATC 寄存器为零（新卡没完成联机处理），则卡应请求联机处理
			if (isCPPSupportNewCardCheck && Util.getShort(abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC) == 0x00) {
				// 将 CVR 的第 3 字节第 5 位设置为‘1’（新卡）
				PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_NEW_CARD);
				return TRADE_RESULT_ARQC;
			}
			
			// 如果支持 PIN 尝试超过检查（卡片附加处理的第 1 字节第4 位=‘1’）同时脱机 PIN 尝试计数器（标签“9F17”）存在并等于零（没有剩余的 PIN 尝试），
			// 则卡应请求联机处理
			if (isCPPSupportPINCheck
				&& (paramBuf[PBOC_PARAM_OFF_PIN_MAX_CNTR] != 0x00) 
				&& (paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] == 0x00)) {
				// 将 CVR 的第 3 字节第 7 位设置为‘1’（PIN 尝试上限超过）				
				PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_BLOCKED);
				return TRADE_RESULT_ARQC;
			}
		}
		
		/**
		 * 5. 脱机货币检查
		 * 当交易货币匹配应用货币，执行脱机消费检查。如果货币不匹配，跳过这些检查并执行不匹配货币处理
		 * 检查处理是匹配还是非匹配货币，以及是否支持脱机消费检查类型的相应检查
		 * 小额检查、小额和CTTA检查、小额或CTTA检查是qPBOC的三种检查脱机消费的方法
		 */
		if (bIsTradeCoinMatch) {
			Util.arrayCopyNonAtomic(abyCurTradeCardData, sECBalanceOff, tmpBuf, (short)0x00, (short)0x06);
			
			// 分段扣费交易处理
			byte extAppType = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_TYPE];
			if (extAppType == EXTEND_APP_TRADE_TYPE_SP) {
	            // 第14部分 5.2.7 支持分段扣费押金抵扣功能的特殊处理
	            // 如果卡片支持分段扣费押金抵扣功能(即支持0xDF62)
	            // 计算当前实际可用电子现金余额=电子现金余额（9F79）+分段扣费抵扣限额（DF62）-分段扣费已抵扣金额（DF63）
				if (!PBOCUtil.isAllZero(cardDataBuf, CARD_DATA_OFF_SP_DEDUCTION_LIMIT, (short)0x06)) {
					PBOCUtil.arrayDecAdd(tmpBuf, (short)0x00, cardDataBuf, CARD_DATA_OFF_SP_DEDUCTION_LIMIT, tmpBuf, (short)0x00);
					PBOCUtil.arrayDecSub(tmpBuf, (short)0x00, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, tmpBuf, (short)0x00);
					
					// 第14部分 5.2.2 初始化应用
		            // 如果当前实际可用电子现金余额小于当前交易金额，则进入标准qPBOC流程，判断拒绝交易还是请求联机；
		            // 如果当前实际可用电子现金余额大于等于当前交易金额，则以当前实际可用电子现金余额替代
		            // 电子现金余额（9F79）进行小额检查等相关操作（预付处理除外，仍使用电子现金余额（9F79）作为判断依据）。
					if (PBOCUtil.arrayCompare(tmpBuf, (short)0x00, pdolValue, sQPDOLTradeAuthMoneyOff, (short)0x06) == -1) {
						Util.arrayCopyNonAtomic(abyCurTradeCardData, sECBalanceOff, tmpBuf, (short)0x00, (short)0x06);
					}
				}
			} else if (extAppType == EXTEND_APP_TRADE_TYPE_OPC){
				// 脱机预授权完成交易
				// 6.2.2 如果CAPP交易指示位为“3”，计算新的电子现金余额=电子现金余额+脱机预授权金额
				PBOCUtil.arrayDecAdd(tmpBuf, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY, tmpBuf, (short)0x00);
				if (PBOCUtil.arrayCompare(tmpBuf, (short)0x00, pdolValue, sQPDOLTradeAuthMoneyOff, (short)0x06) == -1) {
					Util.arrayCopyNonAtomic(abyCurTradeCardData, sECBalanceOff, tmpBuf, (short)0x00, (short)0x06);
				}
			}
						
			/**
			 * 6. 匹配货币交易的小额检查
			 * 这个检查通过卡上的小额上限（电子现金余额上限）来实现。非接触交易的脱机消费可用总资金就是电子现金余额。
			 * 执行这个选项能够来提供等于电子现金余额的可用脱机消费金额
			 * 如果支持小额检查（卡片附加处理的第 1 字节第 8 位=‘1’），则电子现金余额就是总的脱机，接着执行小额检查
			 */
			if (isCPPSupportECCheck) {
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_QPBOC_OFFLINE_CHECK] = QPBOC_OFFLINE_CHECK_TYPE_EC_CHECK;
				
				/**
				 * 10. 小额检查
				 * 检查交易是否能够脱机处理
				 * 如果授权金额（标签“9F02”）小于或等于电子现金单笔交易限额，同时在交易的电子现金余额中有足够的脱机消费可用金额，则交易进行脱机处理
				 * 否则（即如果授权金额大于电子现金单笔交易限额或者交易没有足够的脱机消费可用金额）：
				 * 如果可以联机处理，则卡片请求联机处理
				 * 如果不能联机处理，则卡片请求拒绝
				 */
				
				// 设置脱机可用余额为电子现金余额
				Util.arrayCopyNonAtomic(abyCurTradeCardData, sECBalanceOff, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06);
				// 仅当终端支持脱机时（终端交易属性，第1字节第4位=‘1’）
				// 如果授权金额大于电子现金余额或者大于电子现金单笔交易限额（如果存在），则卡应准备返回可用脱机消费金额（如支持获取），同时拒绝交易
				if (bIsOnlySupportOffline) {
					if ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x00, (short)0x06) == 1)
						|| (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, sSingleCardLimitOff, (short)0x06) == 1)) {
						// 设置 CVR 的第 3 字节第 6 位为‘1’（频度检查计数器超过）
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
						return TRADE_RESULT_AAC;
					}					
				} else {
					// 当终端具有联机能力时（终端交易属性，第1字节第4位=‘0’）
					// 1. 如果授权金额（标签“9F02”）大于电子现金单笔交易限额（如果存在，标签“9F78”），则卡应准备返回可用脱机消费金额（如支持的话），并请求联机处理
					// 2. 如果授权金额（标签“9F02”）大于电子现金余额减去电子现金重置阈值（如果存在，标签“9F6D”），则卡应准备返回可用脱机消费金额（如支持获取），并请求联机处理
					
					// 电子现金重置阈值加上授权金额
					PBOCUtil.arrayDecAdd(cardDataBuf, sECResetThresholdOff, pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x06);
					if ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, sSingleCardLimitOff, (short)0x06) == 1)
						|| (PBOCUtil.arrayCompare(tmpBuf, (short)0x06, tmpBuf, (short)0x00, (short)0x06) == 1)) {
						// 设置 CVR 的第 3 字节第 6 位为‘1’（频度检查计数器超过）
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
						return TRADE_RESULT_ARQC;						
					}
				}
				
				return TRADE_RESULT_TC;
			}
						
			/**
			 * 7. 匹配货币交易的小额和 CTTA 检查
			 * 此部分检查CTTA是否超过累计脱机交易金额上限（CTTAUL）或者在CTTAUL不存在的情况下是否超过累计脱机交易金额限制数CTTAL
			 * 如果CTTA可用资金——CTTAUL（如果不存在用CTTAL）减去CTTA是可用的，同样会检查交易金额是否超过电子现金单笔交易限额
			 * 只有当小额和CTTA检查通过时，脱机交易才会发生
			 * 继续进行的步骤见11——小额和CTTA检查
			 */
			if (isCPPSupportECAndCTTACheck) {
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_QPBOC_OFFLINE_CHECK] = QPBOC_OFFLINE_CHECK_TYPE_EC_AND_CTTA_CHECK;
				
				/**
				 * 11. 小额和CTTA 检查
				 * 检查交易是否能够脱机进行处理
				 * 如果授权金额（标签 “9F02” ）小于或等于电子现金单笔交易限额， 并且交易的电子现金余额和CTTA可用资金都有足够的脱机资金，则交易脱机处理。
				 * 否则[即，如果授权金额（标签“9F02”）大于电子现金单笔交易限额或者交易没有足够的可用脱机消费金额]：
				 * 如果可以联机处理，则卡片请求联机处理
				 * 如果不能联机，则卡片请求拒绝
				 */
				if (bCTTAULNotExist) {
					// CTTAUL不存在, 使用CTTAL
					PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, tmpBuf, (short)0x06);
				} else {
					PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, tmpBuf, (short)0x06);
				}
				
				// 设置脱机可用余额
				Util.arrayCopyNonAtomic(tmpBuf, (short)0x06, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06);
				
				// 仅支持脱机
				if (bIsOnlySupportOffline) {
					/**
					 * 1. 授权金额（标签“9F02”）大于电子现金余额
					 * 2. 授权金额大于电子现金单笔交易限额
					 * 3. 授权金额加上 CTTA 大于 CTTAUL（或者是 CTTAL 如果 CTTAUL 不存在）
					 */
					if ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, CARD_DATA_OFF_SINGLE_CARD_LIMIT, (short)0x06) == 1)
						|| (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x00, (short)0x06) == 1)
						|| (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x06, (short)0x06) == 1)) {
						// 设置 CVR 的第 3 字节第 6 位为‘1’（频度检查计数器超过）
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
						return TRADE_RESULT_AAC;
					}
				} else {
					
					/**
					 * 1. 授权金额（标签“9F02”）大于电子现金单笔交易限额（如果存在，标签“9F78”）
					 * 2. 授权金额（标签“9F02”）大于电子现金余额（标签“9F79”）减去电子现金重置阈值（标签“9F6D”）
					 * 3. 授权金额（标签“9F02”）加上CTTA 大于 CTTAUL/CTTAL（标签“9F54”）
					 */

					// 电子现金重置阈值加上授权金额
					PBOCUtil.arrayDecAdd(cardDataBuf, CARD_DATA_OFF_EC_RESET_THRESHOLD, pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)12);
					
					if ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, CARD_DATA_OFF_SINGLE_CARD_LIMIT, (short)0x06) == 1)
						|| (PBOCUtil.arrayCompare(tmpBuf, (short)12, tmpBuf, (short)0x00, (short)0x06) == 1)
						|| (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x06, (short)0x06) == 1)) {
						// 设置 CVR 的第 3 字节第 6 位为‘1’（频度检查计数器超过）
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
						return TRADE_RESULT_ARQC;						
					}
				}
				
				return TRADE_RESULT_TC;
			}
			
			/**
			 * 8. 匹配货币交易的小额或 CTTA 检查
			 * 此部分检查是否超过电子现金单笔交易限额（如果存在）。如果小额资金不可用，则检查是否超过累计交易总额上限（CTTAL）。
			 * 只有小额或者CTTA资金任一可用，脱机处理才会发生
			 * 如果支持小额或 CTTA 检查（卡片附加处理的第 1 字节第 6 位=‘1’），则脱机资金应在小额或者 CTTA 中可用
			 * 继续进行的步骤见12——小额或CTTA检查
			 */
			if (isCPPSupportECOrCTTACheck) {
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_QPBOC_OFFLINE_CHECK] = QPBOC_OFFLINE_CHECK_TYPE_EC_OR_CTTA_CHECK;
				
				/**
				 * 12. 小额或CTTA 检查
				 * 检查交易能否脱机处理
				 * 如果授权金额（标签“9F02”）小于或等于单笔交易限额，并且电子现金余额或者CTTA中有足够的脱机资金，那么交易可以脱机处理。
				 * 否则（也即如果授权金额（标签“9F02”）大于电子现金单笔交易限额或者没有足够的可用脱机消费金额）： 
				 * 如果允许联机交易，那么卡片请求联机处理
				 * 如果不允许联机交易，那么卡片将请求拒绝
				 * 对于该选项，可用脱机消费金额等于CTTA可用余额和电子现金余额的总和
				 */
				
				if (bCTTAULNotExist) {
					// CTTAUL不存在, 使用CTTAL
					PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, tmpBuf, (short)0x06);
				} else {
					PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, tmpBuf, (short)0x06);
				}
				
				// 设置脱机可用余额, 可用脱机消费金额（标签“9F5D”）的值设为电子现金余额加上CTTAUL（或者是CTTAL如果CTTAUL不存在），再减去CTTA
				PBOCUtil.arrayDecAdd(tmpBuf, (short)0x06, abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
				
				// 仅支持脱机
				if (bIsOnlySupportOffline) {
					// 1. 如果授权金额大于电子现金单笔交易限额
					// 2. 授权金额大于电子现金余额并且授权金额加上CTTA 大于 CTTAUL/CTTAL
					if ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, CARD_DATA_OFF_SINGLE_CARD_LIMIT, (short)0x06) == 1)
						|| ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x00, (short)0x06) == 1)
							&& (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x06, (short)0x06) == 1))) {
						// 设置 CVR 的第 3 字节第 6 位为‘1’（频度检查计数器超过）
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
						return TRADE_RESULT_AAC;
					}					
				} else {
					// 1. 授权金额（标签“9F02”）大于电子现金单笔交易限额（如果存在，标签“9F78”）
					// 2. 如果授权金额（标签 “9F02” ）大于电子现金余额（标签 “9F79” ），并且授权金额（标签 “9F02” ）加上 CTTA（无标签）大于 CTTAUL/CTTAL（标签“9F54”）
					// 联机交易
					if ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, cardDataBuf, CARD_DATA_OFF_SINGLE_CARD_LIMIT, (short)0x06) == 1)
						|| ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x00, (short)0x06) == 1)
							&& (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, tmpBuf, (short)0x06, (short)0x06) == 1))) {
						// 设置 CVR 的第 3 字节第 6 位为‘1’（频度检查计数器超过）
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
						return TRADE_RESULT_ARQC;
					}
				}
				
				return TRADE_RESULT_TC;
			}
			
			/**
			 * 9. 没有任何脱机选项被支持 
			 */
			// 如果是终端仅支持脱机（终端交易属性，第 1 字节第 4 位=‘1’），则卡片应当拒绝交易
			if (bIsOnlySupportOffline) {
				return TRADE_RESULT_AAC;
			}
			
			// 如果终端支持联机（终端交易属性，第 1 字节第 4 位=‘0’），则卡片应请求联机处理
			// 卡要将可用脱机消费金额设置为零。
			Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06, (byte)0x00);
			
			return TRADE_RESULT_ARQC;
		} else {
			/**
			 * 13. 脱机下的货币不匹配
			 * 如果应用货币与交易货币不匹配，要检查这些交易的上限是否超额
			 */
			short sInterCoinOffLineATC = (short)(abyCurTradeCardData[CARD_DATA_OFF_INTERCOINOFFLINE_ATC]&0x0FF);
			short sCoinOffLineTradeLimit = (short)(cardDataBuf[CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT]&0x0FF);
			
			if (sInterCoinOffLineATC >= sCoinOffLineTradeLimit) {
				// 将CVR第3字节第6位置为‘1’（频度检查计数器超过）
				PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
				
				if (bIsOnlySupportOffline) {
					return TRADE_RESULT_AAC;
				}
				
				return TRADE_RESULT_ARQC;
			}
			
			abyCurTradeCardData[CARD_DATA_OFF_INTERCOINOFFLINE_ATC]++;
			
			// 脱机货币不匹配，卡片支持小额检查，设置可用脱机消费金额为电子现金余额
			calAvailableMoney();
			
			return TRADE_RESULT_TC;
		}
	}
	
	/**
	 * generate issue application data
	 * @param issueAppData	issue application data buffer
	 * @param sOff			issue application data buffer offset
	 * @param sIssueLen		issue application data length
	 */
	private void generateIssueAppData(byte[] issueAppData, short sOff, short sIssueLen) {
		// copy CVR
		Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, issueAppData, (short) (sOff+0x04), (short) 0x03);
		
		short sLen = (short) (issueAppData[sOff] + 0x02);
		if (sIssueLen > sLen) {
			short sTmp = (short)(sOff + sLen);
			
			switch (issueAppData[sTmp++]) {
			case 0x01:
				// 电子现金余额低5个字节
				short sECOff;
				if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE]) {
					sECOff = CARD_DATA_OFF_EC_SECOND_BALANCE;
				} else {
					sECOff = CARD_DATA_OFF_EC_BALANCE;
				}
				Util.arrayCopyNonAtomic(abyCurTradeCardData, (short)(sECOff+0x01), issueAppData, sTmp, (short)0x05);
				sLen = 0x05;
				break;
			case 0x02:
				// 累计交易总金额(CTTA)低5个字节
				Util.arrayCopyNonAtomic(abyCurTradeCardData, (short)(CARD_DATA_OFF_TOTAL_OFFILINE_MONEY+0x01), issueAppData, sTmp, (short)0x05);
				sLen = 0x05;
				break;
			case 0x03:
				// 电子现金余额低5个字节和CTTA低5个字节
				Util.arrayCopyNonAtomic(abyCurTradeCardData, (short)(CARD_DATA_OFF_EC_BALANCE+0x01), issueAppData, sTmp, (short)0x05);
				Util.arrayCopyNonAtomic(abyCurTradeCardData, (short)(CARD_DATA_OFF_TOTAL_OFFILINE_MONEY+0x01), issueAppData, (short)(sTmp+0x05), (short)0x05);
				sLen = 10;
				break;
			case 0x04:
				// CTTA低5个字节和CTTAL低5个字节
				Util.arrayCopyNonAtomic(abyCurTradeCardData, (short)(CARD_DATA_OFF_TOTAL_OFFILINE_MONEY+0x01), issueAppData, sTmp, (short)0x05);
				Util.arrayCopyNonAtomic(cardDataBuf, (short)(CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT+0x01), issueAppData, (short)(sTmp+0x05), (short)0x05);
				sLen = 10;
				break;
			case 0x05:
				// 可用脱机消费金额低5个字节
				Util.arrayCopyNonAtomic(abyCurTradeCardData, (short)(CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY+0x01), issueAppData, sTmp, (short)0x05);
				sLen = 0x05;
				break;
			default:
				issueAppData[sOff] = (byte) sLen;
				return;
			}

			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
			sessionKey[0x06] = cardDataBuf[CARD_DATA_OFF_ATC];
			sessionKey[0x07] = cardDataBuf[(short)(CARD_DATA_OFF_ATC+0x01)];			
			sessionKey[14] = (byte)(~sessionKey[0x06]);
			sessionKey[15] = (byte)(~sessionKey[0x07]);
			
			// generate APP Session Key
			tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_MAC_KEY);
			cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
			
			tripleDesKey.setKey(sessionKey, (short) 0x00);
			
			// cal mac
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
			// ATC			
			sessionKey[0x00] = cardDataBuf[CARD_DATA_OFF_ATC];
			sessionKey[0x01] = cardDataBuf[(short)(CARD_DATA_OFF_ATC+0x01)];
			// Data
			Util.arrayCopyNonAtomic(issueAppData, sTmp, sessionKey, (short)0x02, sLen);
			
			short sCalData;
			if (sLen == 0x05) {
				sCalData = 0x08;
			} else {
				sCalData = 0x10;
			}
			
			signMac.sign(sessionKey, (short) 0, sCalData, sessionKey, (short)0x00);
			
			Util.arrayCopyNonAtomic(sessionKey, (short)0x00, issueAppData, (short)(sTmp+sLen), (short) 0x04);
		}		
	}
	
	/**
	 * generate Application cipher
	 * @param cdolValue	CDOL Value buffer
	 */
	private void generateAppCipher(byte[] cdolValue) {	
		Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
		Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);
		Util.arrayCopyNonAtomic(sessionKey, (short)0x06, sessionKey, (short)14, (short)0x02);
		sessionKey[14] ^= (byte)0xFF;
		sessionKey[15] ^= (byte)0xFF;
		
		// generate APP Session Key
		tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_APP_KEY);
		cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
		
		tripleDesKey.setKey(sessionKey, (short) 0x00);
		
		short tradeAuthMoneyOff;
		short tradeOtherMoneyoff;
		short stateCodeOff;
		short tvrOff;
		short tradeCoinCodeOff;
		short tradeDateOff;
		short tradeTypeOff;
		short randomOff;
		
		if (cdolValue == cdol1Value) {
			tradeAuthMoneyOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY]&0x0FF);
			tradeOtherMoneyoff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_OTHER_MONEY]&0x0FF);
			stateCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TERMINAL_STATE_CODE]&0x0FF);
			tvrOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TVR]&0x0FF);
			tradeCoinCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_COIN_CODE]&0x0FF);
			tradeDateOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_DATE]&0x0FF);
			tradeTypeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_TYPE]&0x0FF);
			randomOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TERMINAL_TRADE_RANDOM]&0x0FF);
		} else {
			tradeAuthMoneyOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY]&0x0FF);
			tradeOtherMoneyoff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_OTHER_MONEY]&0x0FF);
			stateCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TERMINAL_STATE_CODE]&0x0FF);
			tvrOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TVR]&0x0FF);
			tradeCoinCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_COIN_CODE]&0x0FF);
			tradeDateOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_DATE]&0x0FF);
			tradeTypeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_TYPE]&0x0FF);
			randomOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TERMINAL_TRADE_RANDOM]&0x0FF);
		}
		
		// 密文版本号1
		if (pbocIssueAppData[0x02] == AC_VERSION_01) {
			// 终端参与应用密文计算的数据
			// 6 byte, 授权金额
			signMac.update(cdolValue, tradeAuthMoneyOff, (short)0x06);		
			// 6 byte, 其他金额			
			signMac.update(cdolValue, tradeOtherMoneyoff, (short)0x06);
			// 2 byte, 终端国家代码			
			signMac.update(cdolValue, stateCodeOff, (short)0x02);
			// 5 byte, 终端验证结果			
			signMac.update(cdolValue, tvrOff, (short)0x05);
			// 2 byte, 交易货币代码			
			signMac.update(cdolValue, tradeCoinCodeOff, (short)0x02);
			// 3 byte, 交易日期			
			signMac.update(cdolValue, tradeDateOff, (short)0x03);
			// 1 byte, 交易类型			
			signMac.update(cdolValue, tradeTypeOff, (short)0x01);
			// 4 byte, 不可预知数			
			signMac.update(cdolValue, randomOff, (short)0x04);
			
			// 卡片参与应用密文计算的数据
			// 2 byte, AIP			
			signMac.update(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, (short)0x02);
			// 2 byte, ATC			
			signMac.update(cardDataBuf, CARD_DATA_OFF_ATC, (short)0x02);
			// 4 byte, LV CVR
			sessionKey[0x00] = 0x03;
			signMac.update(sessionKey, (short)0x00, (short)0x01);
			signMac.sign(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, (short)0x03, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC);	
		} else {
			// 密文版本号17
			
			// 终端参与应用密文计算的数据
			// 6 byte, 授权金额		
			signMac.update(cdolValue, tradeAuthMoneyOff, (short)0x06);
			// 4 byte, 不可预知数			
			signMac.update(cdolValue, randomOff, (short)0x04);
			
			// 卡片参与应用密文计算的数据
			// 2 byte, ATC			
			signMac.update(cardDataBuf, CARD_DATA_OFF_ATC, (short)0x02);
			// 发卡行应用数据第五个字节
			signMac.sign(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, (short)0x01, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC);			
		}
	}
	
	/**
	 * QPBOC GPO Process
	 * @param apduBuf	apdu buffer
	 * @return response data length
	 */
	private short qPBOCGPOProcess(byte[] apduBuf) {
		byte extAppType = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_TYPE];
		if (extAppType == EXTEND_APP_TRADE_TYPE_OP) {
			// FORT BCTC testcase PRSS002, not read Extend Application File and GPO command give a valid Extend Application Trade Type Value
			if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI] == 0x00) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			
			// 如果 CAPP 交易指示位为 2， 对于同一行业的同一应用（ 即相同 SFI 的扩展应用文件下相同 ID 的记录）
			// 不允许连续脱机预授权交易发生，如果卡片收到连续脱机预授权交易 ，则返回6972
			if (getPreAuthTradeMoney(null, (short)0x00)) {
				ISOException.throwIt((short)0x6972);
			}
			
			if (!getPreAuthContextSpace()) {
				// 目前同时支持3个脱机预授权交易，对应3个不同的内部脱机预授权金额
				// 如果卡片收到第4个脱机预授权交易的 GPO 命令时，则卡片返回6971
				ISOException.throwIt((short)0x6971);
			}			
		} else if (extAppType == EXTEND_APP_TRADE_TYPE_OPC) {
			// FORT BCTC testcase PRSS002, not read Extend Application File and GPO command give a valid Extend Application Trade Type Value
			if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI] == 0x00) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			
			// 如果CAPP交易指示位为3，但是卡片无对应脱机预授权交易，则卡片返回6973
			if (!getPreAuthTradeMoney(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY)) {
				ISOException.throwIt((short)0x6973);
			}
		}
		
		boolean bIsECSecond = false;
		boolean bIsTradeCoinMatch = false;
		if (Util.arrayCompare(pdolValue, sQPDOLTradeCoinCodeOff, cardDataBuf, CARD_DATA_OFF_APPCOINCODE, (short)0x02) == 0x00) {			
			bIsTradeCoinMatch = true;
		} else if ((Util.arrayCompare(pdolValue, sQPDOLTradeCoinCodeOff, cardDataBuf, CARD_DATA_OFF_EC_SECOND_APP_COIN_CODE, (short)0x02) == 0x00) && isCPPSupportECCheck) {
			bIsECSecond = true;
			bIsTradeCoinMatch = true;
		}
		
		curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE] = bIsECSecond;
		byte tradeResult = qPBOCCardRiskManager(apduBuf, bIsTradeCoinMatch, bIsECSecond);
		
		if (TRADE_RESULT_ABORT == tradeResult) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}				
				
		// set CVR 2nd generate ac
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] |= CVR_2ND_GEN_AC_NO_REQ;
		
		short sLen;
		if (TRADE_RESULT_TC == tradeResult) {
			/**
			 * 1. 货币匹配
			 * 2. 交易结果为脱机同意
			 */
			if (bIsTradeCoinMatch) {
				short sECBalanceOff;
				if (bIsECSecond) {
					sECBalanceOff = CARD_DATA_OFF_EC_SECOND_BALANCE;
				} else {
					sECBalanceOff = CARD_DATA_OFF_EC_BALANCE;
				}
				
				// 分段扣费交易处理
				if (extAppType == EXTEND_APP_TRADE_TYPE_SP) {
			        // 第14部分 5.2.7 支持分段扣费押金抵扣功能的特殊处理
			        // 如果卡片支持押金抵扣功能且电子现金余额（9F79）小于当前交易金额，则进行押金抵扣，
			        // 交易后的分段扣费已抵扣金额（DF63）=交易前分段扣费已抵扣金额（DF63）+交易金额-交易前电子现金余额（9F79）。
					if (PBOCUtil.arrayCompare(abyCurTradeCardData, sECBalanceOff, pdolValue, sQPDOLTradeAuthMoneyOff, (short)0x06) == -1) {
						// if EC Balance is not 0
						// remain = trade auth money - EC Balance
						PBOCUtil.arrayDecSub(pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff, abyCurTradeCardData, sECBalanceOff);
						
						// DF63 += remain
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, abyCurTradeCardData, sECBalanceOff, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY);
						Util.arrayFillNonAtomic(abyCurTradeCardData, sECBalanceOff, (short)0x06, (byte)0x00);
					} else {
						PBOCUtil.arrayDecSub(abyCurTradeCardData, sECBalanceOff, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff);
					}
				} else if (extAppType == EXTEND_APP_TRADE_TYPE_OPC) {
				    // 6.2.7 脱机预授权完成交易时，如果脱机预授权完成金额大于等于脱机预授权金额，
				    // 则电子现金余额=电子现金余额+脱机预授权金额-脱机预授权完成金额
					if (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY, (short)0x06) == 0x01) {
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, sECBalanceOff, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY, abyCurTradeCardData, sECBalanceOff);
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
						
						PBOCUtil.arrayDecSub(abyCurTradeCardData, sECBalanceOff, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff);
					} else {
			    		// 6.2.7 脱机预授权完成交易时，如果脱机预授权完成金额小于脱机预授权金额，且分段扣费已抵扣金额（ DF63 ）大于零，
			    		// 脱机预授权剩余金额 = 脱机预授权金额 - 脱机预授权完成金额；
			    		// 如果脱机预授权剩余金额大于分段扣费已抵扣金额 （ DF63 ），则将分段扣费已抵扣金额 （ DF63 ）清零，
			    		// 同时设置当前电子现金余额（ 9F79 ） = 脱机预授权剩余金额 - 分段扣费已抵扣金额（ DF63 ）；
			    		// 如果脱机预授权剩余金额小于等于分段扣费已抵扣金额 （ DF63 ），则设置当前分段扣费已抵扣金额（ DF63 ） = 交易前分段扣费已抵扣金额（ DF63 ） - 脱机预授权剩余金额 。
						if (PBOCUtil.isAllZero(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, (short)0x06)) {
							PBOCUtil.arrayDecAdd(abyCurTradeCardData, sECBalanceOff, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY, abyCurTradeCardData, sECBalanceOff);
							PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
							
							PBOCUtil.arrayDecSub(abyCurTradeCardData, sECBalanceOff, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff);
						} else {
							// 脱机预授权金额 - 脱机预授权完成金额
							PBOCUtil.arrayDecSub(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_PRE_AUTH_MONEY, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff);
							// 如果脱机预授权剩余金额小于等于分段扣费已抵扣金额 （ DF63 ），则设置当前分段扣费已抵扣金额（ DF63 ） = 交易前分段扣费已抵扣金额（ DF63 ） - 脱机预授权剩余金额 。
							if (PBOCUtil.arrayCompare(abyCurTradeCardData, sECBalanceOff, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, (short)0x06) == -1) {
								PBOCUtil.arrayDecSub(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, abyCurTradeCardData, sECBalanceOff, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY);
								Util.arrayFillNonAtomic(abyCurTradeCardData, sECBalanceOff, (short)0x06, (byte)0x00);
							} else {
								// 如果脱机预授权剩余金额大于分段扣费已抵扣金额 （ DF63 ）
								// 当前电子现金余额（ 9F79 ） = 脱机预授权剩余金额 - 分段扣费已抵扣金额（ DF63 ）
								PBOCUtil.arrayDecSub(abyCurTradeCardData, sECBalanceOff, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, abyCurTradeCardData, sECBalanceOff);
								// 分段扣费已抵扣金额 （ DF63 ）清零
								Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, (short)0x06, (byte)0x00);																
							}							
						}
					}
				} else {
					switch(abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_QPBOC_OFFLINE_CHECK]) {
					case QPBOC_OFFLINE_CHECK_TYPE_EC_CHECK:
						// 脱机货币检查为小额检查时，新的电子现金余额，等于电子现金余额减去授权金额（标签“9F02”）
						PBOCUtil.arrayDecSub(abyCurTradeCardData, sECBalanceOff, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff);
						break;
					case QPBOC_OFFLINE_CHECK_TYPE_EC_AND_CTTA_CHECK:
						// 脱机货币检查为小额和CTTA检查时
						// 1. 计算新的 CTTA等于 CTTA加上授权金额（标签“9F02”）
						// 2. 计算新的电子现金余额，等于电子现金余额减去授权金额（标签“9F02”）
						PBOCUtil.arrayDecSub(abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE);
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY);
						break;
					case QPBOC_OFFLINE_CHECK_TYPE_EC_OR_CTTA_CHECK:
						// 脱机货币检查为小额或CTTA检查时
						// 1. 电子现金资金可用, 如果授权金额（标签“9F02”）不大于电子现金余额（标签“9F79”），那么保存电子现金余额值并计算新的电子现金余额=电子现金余额－授权金额（标签“9F02”）
						// 2. 电子现金资金不可用从而用 CTTA 资金, 如果授权金额（标签“9F02”）大于电子现金余额（标签“9F79”），那么保存CTTA，并计算新的CTTA=CTTA加上授权金额。
						if (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE, (short)0x06) == 1) {
							PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY);
						} else {
							PBOCUtil.arrayDecSub(abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE);
						}				
						break;
					}								
				}
				
				// 若交易脱机同意，可用脱机余额则还需减去授权金额
				PBOCUtil.arrayDecSub(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY);
			}
			
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_1ST_GEN_AC_MASK))|CVR_1ST_GEN_AC_RETURN_TC);
			
			// update AC
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
			sessionKey[0x06] = cardDataBuf[CARD_DATA_OFF_ATC];
			sessionKey[0x07] = cardDataBuf[(short)(CARD_DATA_OFF_ATC+0x01)];			
			sessionKey[14] = (byte)(~sessionKey[0x06]);
			sessionKey[15] = (byte)(~sessionKey[0x07]);
			
			// generate APP Session Key
			tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_APP_KEY);
			cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
			
			tripleDesKey.setKey(sessionKey, (short) 0x00);
			
			// 密文版本号1
			sLen = 0x00;
			if (qpbocTCGPORsp[(short)(sQPBOCTCRspIssueAppOff+0x02)] == AC_VERSION_01) {
				// 终端参与应用密文计算的数据
				// 6 byte, 授权金额
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeAuthMoneyOff, apduBuf, (short)0x00, (short)0x06);		
				// 6 byte, 其他金额							
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeOtherMoneyOff, apduBuf, (short)0x06, (short)0x06);
				// 2 byte, 终端国家代码
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalStateCodeOff, apduBuf, (short)12, (short)0x02);				
				// 5 byte, 终端验证结果							
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalResultOff, apduBuf, (short)14, (short)0x05);
				// 2 byte, 交易货币代码							
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeCoinCodeOff, apduBuf, (short)19, (short)0x02);
				// 3 byte, 交易日期				
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeDateOff, apduBuf, (short)21, (short)0x03);
				// 1 byte, 交易类型
				apduBuf[(short)24] = pdolValue[sQPDOLTradeTypeOff];				
				// 4 byte, 不可预知数
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalTradeRandomOff, apduBuf, (short)25, (short)0x04);				
				
				// 卡片参与应用密文计算的数据
				// 2 byte, AIP				
				Util.arrayCopyNonAtomic(paramBuf, PBOC_PARAM_OFF_QPBOC_AIP, apduBuf, (short)29, (short)0x02);
				// 2 byte, ATC
				Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, (short)31, (short)0x02);			
				// 4 byte, LV CVR
				apduBuf[33] = 0x03;
				Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, apduBuf, (short)34, (short)0x03);
				
				signMac.sign(apduBuf, (short)0x00, (short)37, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC);	
			} else {
				// 密文版本号17
				
				// 终端参与应用密文计算的数据
				// 6 byte, 授权金额				
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeAuthMoneyOff, apduBuf, (short)0x00, (short)0x06);
				// 4 byte, 不可预知数				
				Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalTradeRandomOff, apduBuf, (short)0x06, (short)0x04);
				
				// 卡片参与应用密文计算的数据
				// 2 byte, ATC							
				 Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, (short)10, (short)0x02);
				// 发卡行应用数据第五个字节
				apduBuf[12] = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR];
				
				signMac.sign(apduBuf, (short)0x00, (short)13, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC);
			}			
			
			sLen = (short)qpbocTCGPORsp.length;
			// get gpo tc response template
			Util.arrayCopyNonAtomic(qpbocTCGPORsp, (short)0x00, apduBuf, (short)0x00, sLen);
			
			// update ATC
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, sQPBOCTCRspATCOff, (short)0x02);
			
			// 生成发卡行自定义数据					
			generateIssueAppData(apduBuf, sQPBOCTCRspIssueAppOff, apduBuf[(short)(sQPBOCTCRspIssueAppOff-0x01)]);
			// copy ac
			Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC, apduBuf, sQPBOCTCRspACOff, (short)0x08);
			
			if (bIsQPBOCSupportDDA) {
				short sDDALen = (short)ddaTemplate.length;				
				if (sDDALen <= 0x80) {					
					Util.arrayCopyNonAtomic(ddaTemplate, (short)0x00, apduBuf, sQPBOCTCRspICCSIGOff, sDDALen);
					Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, (short)(sQPBOCTCRspICCSIGOff+DDA_OFF_IC_DATA_DIGIT), (short)0x02);
					
					msgDigest.update(apduBuf, (short)(sQPBOCTCRspICCSIGOff+DDA_OFF_SIGN_FORMAT), (short)(sDDALen-22));
					
					if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_FDDA_VERSION) && bIsPBOC3) {
						// fDDA version 00 用于输入DDA哈希算法的终端动态数据
						// 标签 数据元素 				长度 	数据来源
						// 9F37 不可预知数			4字节	终端
						// 9F02 授权金额 				6字节 	终端
						// 5F2A 交易货币代码 			2字节 	终端
						// 9F69 卡片认证相关数据 		可变 	卡片 (12部分附录C 注：在本版本规范中，卡片认证相关数据使用8个字节长度，并且被个人化到卡片中。)
						// 9F36 应用交易计数器（ATC） 	2字节	卡片
						msgDigest.update(pdolValue, sQPDOLTerminalTradeRandomOff, (short)0x04);
						msgDigest.update(pdolValue, sQPDOLTradeAuthMoneyOff, (short)0x06);
						msgDigest.update(pdolValue, sQPDOLTradeCoinCodeOff, (short)0x02);
						
						// update 卡片认证相关数据
						abyCurTradeCardData[CARD_DATA_OFF_CARD_AUTH_DATA] = 0x01;
						random.generateData(abyCurTradeCardData, (short)(CARD_DATA_OFF_CARD_AUTH_DATA+0x01), (short)0x04);
						Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, abyCurTradeCardData, (short)(CARD_DATA_OFF_CARD_AUTH_DATA+0x05), (short)0x02);
						
				        // 第14部分 5.2.6 结束处理
				        // 如果卡片的fDDA版本号为“01”，则卡片在产生动态签名前应将分段扣费应用标识（DF61）
				        // 的值动态填充到卡片认证相关数据（9F69）的第8个字节中再进行动态签名的运算。
						abyCurTradeCardData[(short)(CARD_DATA_OFF_CARD_AUTH_DATA+0x07)] = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE];
						
						msgDigest.doFinal(abyCurTradeCardData, CARD_DATA_OFF_CARD_AUTH_DATA, (short)0x08, apduBuf, (short)(sQPBOCTCRspICCSIGOff+sDDALen-21));										
					} else {
						abyCurTradeCardData[CARD_DATA_OFF_CARD_AUTH_DATA] = 0x00;
						// fDDA version 00 用于输入DDA哈希算法的终端动态数据
						// 标签 数据元素 				长度 	数据来源
						// 9F37 不可预知数			4字节	终端
						// 9F36 应用交易计数器（ATC） 	2字节	卡片
						msgDigest.doFinal(pdolValue, sQPDOLTerminalTradeRandomOff, (short)0x04, apduBuf, (short)(sQPBOCTCRspICCSIGOff+sDDALen-21));
					}
										
					cipherRSA.doFinal(apduBuf, sQPBOCTCRspICCSIGOff, sDDALen, apduBuf, sQPBOCTCRspICCSIGOff);								
				}								
			}
			
			// update card trade attribute
			Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, apduBuf, sQPBOCTCRspCardAttrOff, (short)0x02);
															
			// update 9F5D
			if (sQPBOCTCRspAvailMoneyOff != INVALID_VALUE) {
				Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, apduBuf, sQPBOCTCRspAvailMoneyOff, (short)0x06);
			}
			
			if (extAppType == EXTEND_APP_TRADE_TYPE_OP) {
				short sTmp = (short)(sQPBOCTCRspACOff+0x08);
				Util.arrayCopyNonAtomic(apduBuf, sTmp, apduBuf, (short)(sQPBOCTCRspACOff-0x03), (short)(sLen-sTmp));
				sLen -= 11;
				sTmp = (short)(apduBuf[0x01]&0x0FF);
				boolean bFlag = false;
				if (sTmp == 0x81) {
					bFlag = true;
					sTmp = (short)(apduBuf[0x02]&0x0FF);
				} 

				sTmp -= 11;
				if (bFlag) {
					if (sTmp < 0x80) {
						apduBuf[0x01] = (byte)sTmp;
						Util.arrayCopyNonAtomic(apduBuf, (short)0x03, apduBuf, (short)0x02, sTmp);
						sLen--;
					} else {
						apduBuf[0x02] = (byte)sTmp;
					}
				} else {
					apduBuf[0x01] = (byte)sTmp;
				}
			}
		} else {
			// ARQC和AAC
			
			calAvailableMoney();
			if (TRADE_RESULT_ARQC == tradeResult) {
				/**
				 * 如果卡片要求接触式借记/贷记联机（卡片附加处理，第1字节第2位），
				 * 而且终端支持接触借记/贷记（终端交易属性第1字节第5位），
				 * 那么卡片应当请求交易终止；如果终端不支持接触式借记/贷记，继续完成联机交易。
				 */
				if (isCPPFstContactPBOCOnline && PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_CONTACT_PBOC)) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				
				// 检查预付支持
				// 如果支持预付（卡片附加处理，第 2 字节第 8 位=‘1’）
				// 如果授权金额为零，拒绝交易
				if (isCPPSupportPrePay) {
					// 授权金额为0
					if (PBOCUtil.isAllZero(pdolValue, sQPDOLTradeAuthMoneyOff, (short)0x06)) {
						tradeResult = CVR_1ST_GEN_AC_RETURN_AAC;
					} else {
						/**
						 * 小额和 CTTA 预付
						 */
						if (isCPPSupportECAndCTTACheck) {
							if (bCTTAULNotExist) {
								// CTTAUL不存在, 使用CTTAL
								PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, apduBuf, (short)0x00);
							} else {
								PBOCUtil.arrayDecSub(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, apduBuf, (short)0x00);
							}
							
							// 预付且资金不足
							// 1. 授权金额（标签“9F02”）大于电子现金余额（标签“9F79”）
							// 2. 授权金额加上CTTA大于CTTAUL（如果CTTAUL不存在，使用CTTAL）
							// 卡片应当请求拒绝交易
							if ((PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE, (short)0x06) == 1)
								|| (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, apduBuf, (short)0x00, (short)0x06) == 1)) {
								tradeResult = CVR_1ST_GEN_AC_RETURN_AAC;
							} else {
								// 预付且资金可用
								// CTTA=CTTA+授权金额
								// 电子现金余额=电子现金余额—授权金额
								// 可用脱机消费金额=CTTAUL（如果CTTAUL不存在，使用CTTAL）－CTTA
								PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY);
								PBOCUtil.arrayDecSub(abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, CARD_DATA_OFF_EC_BALANCE);
								
								PBOCUtil.arrayDecSub(apduBuf, (short)0x00, pdolValue, sQPDOLTradeAuthMoneyOff, apduBuf, (short)0x00);
								Util.arrayCopyNonAtomic(apduBuf, (short)0x00, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06);
								tradeResult = CVR_1ST_GEN_AC_RETURN_ARQC;
							}
						} else if (isCPPSupportECCheck){
							short sECBalanceOff;
							if (bIsECSecond) {
								sECBalanceOff = CARD_DATA_OFF_EC_SECOND_BALANCE;
							} else {
								sECBalanceOff = CARD_DATA_OFF_EC_BALANCE;
							}
							// 小额预付
							// 预付且资金不足, 授权金额（标签“9F02”）大于电子现金余额（标签“9F79”），卡片应请求拒绝
							if (PBOCUtil.arrayCompare(pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff, (short)0x06) == 1) {
								tradeResult = CVR_1ST_GEN_AC_RETURN_AAC;
							} else {
								// 预付且资金可用
								// 电子现金余额=电子现金余额—授权金额
								// 设置可用脱机消费金额=电子现金余额
								PBOCUtil.arrayDecSub(abyCurTradeCardData, sECBalanceOff, pdolValue, sQPDOLTradeAuthMoneyOff, abyCurTradeCardData, sECBalanceOff);
								
								Util.arrayCopyNonAtomic(abyCurTradeCardData, sECBalanceOff, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06);
								
								tradeResult = CVR_1ST_GEN_AC_RETURN_ARQC;
							}
						} else {
							tradeResult = CVR_1ST_GEN_AC_RETURN_ARQC;
						}
					}				
				} else {
					tradeResult = CVR_1ST_GEN_AC_RETURN_ARQC;
				}
			} else {
				tradeResult = CVR_1ST_GEN_AC_RETURN_AAC;
			}
			
			// 如果在卡片附加处理中支持新卡检查（第 1 字节第 5 位），设置上次联机 ATC 寄存器＝ATC
//			if ((tradeResult == CVR_1ST_GEN_AC_RETURN_ARQC)
//				&& isCPPSupportNewCardCheck) {
//				Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_ATC, abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC, (short)0x02);
//			}
			
			// set CVR Trade Result
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_1ST_GEN_AC_MASK))|tradeResult);
			
			// update AC
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);
			Util.arrayCopyNonAtomic(sessionKey, (short)0x06, sessionKey, (short)14, (short)0x02);
			sessionKey[14] ^= (byte)0xFF;
			sessionKey[15] ^= (byte)0xFF;
			
			// generate APP Session Key
			tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_APP_KEY);
			cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
			
			tripleDesKey.setKey(sessionKey, (short) 0x00);
			
			// 密文版本号1
			sLen = 0x00;
			if (qpbocARQCACCGPORsp[(short)(sQPBOCARQCAACRspIssueAPPOff+0x02)] == AC_VERSION_01) {
				// 终端参与应用密文计算的数据
				// 6 byte, 授权金额
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeAuthMoneyOff, apduBuf, (short)0x00, (short)0x06);				
				// 6 byte, 其他金额							
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeOtherMoneyOff, apduBuf, sLen, (short)0x06);
				// 2 byte, 终端国家代码
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalStateCodeOff, apduBuf, sLen, (short)0x02);				
				// 5 byte, 终端验证结果							
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalResultOff, apduBuf, sLen, (short)0x05);
				// 2 byte, 交易货币代码							
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeCoinCodeOff, apduBuf, sLen, (short)0x02);
				// 3 byte, 交易日期				
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeDateOff, apduBuf, sLen, (short)0x03);
				// 1 byte, 交易类型
				apduBuf[sLen++] = pdolValue[sQPDOLTradeTypeOff];				
				// 4 byte, 不可预知数
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalTradeRandomOff, apduBuf, sLen, (short)0x04);				
				
				// 卡片参与应用密文计算的数据
				// 2 byte, AIP				
				sLen = Util.arrayCopyNonAtomic(paramBuf, PBOC_PARAM_OFF_QPBOC_AIP, apduBuf, sLen, (short)0x02);
				// 2 byte, ATC
				sLen = Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, sLen, (short)0x02);			
				// 4 byte, LV CVR
				apduBuf[sLen++] = 0x03;
				sLen = Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, apduBuf, sLen, (short)0x03);				
			} else {
				// 密文版本号17
				
				// 终端参与应用密文计算的数据
				// 6 byte, 授权金额				
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeAuthMoneyOff, apduBuf, (short)0x00, (short)0x06);
				// 4 byte, 不可预知数				
				sLen = Util.arrayCopyNonAtomic(pdolValue, sQPDOLTerminalTradeRandomOff, apduBuf, sLen, (short)0x04);
				
				// 卡片参与应用密文计算的数据
				// 2 byte, ATC							
				sLen = Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, sLen, (short)0x02);
				// 发卡行应用数据第五个字节
				apduBuf[sLen++] = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR];						
			}
			signMac.sign(apduBuf, (short)0x00, sLen, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC);
			
			sLen = (short)qpbocARQCACCGPORsp.length;
			// get gpo arqc/aac response template
			Util.arrayCopyNonAtomic(qpbocARQCACCGPORsp, (short)0x00, apduBuf, (short)0x00, sLen);
			
			// update ATC
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, sQPBOCARQCAACRspATCOff, (short)0x02);
			
			// 生成发卡行自定义数据					
			generateIssueAppData(apduBuf, sQPBOCARQCAACRspIssueAPPOff, apduBuf[(short)(sQPBOCARQCAACRspIssueAPPOff-0x01)]);
			
			Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC, apduBuf, sQPBOCARQCAACRspACOff, (short)0x08);

			// update card trade attribute
			Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, apduBuf, sQPBOCARQCAACRspCardAttrOff, (short)0x02);
						
			// update 9F5D
			if (sQPBOCARQCAACRspAvailMoneyOff != INVALID_VALUE) {
				Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, apduBuf, sQPBOCARQCAACRspAvailMoneyOff, (short)0x06);
			}
						
			Util.arrayCopy(abyCurTradeCardData, CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO, cardDataBuf, CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO, (short)(CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY-CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO));
		}
		
		return sLen;
	}
	
	/**
	 * PBOC GPO Process
	 * @param apduBuf	apdu buffer
	 * @return response data length
	 */
	private short PBOCGPOProcess(byte[] apduBuf) {
		byte[] gpo;
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE]==TRADE_TYPE_EC) {
			gpo = ecGPO;
		} else {
			gpo = pbocGPO;
		}
		
		// not perso
		if (gpo == null) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		// set aip
		Util.arrayCopyNonAtomic(gpo, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, (short)0x02);	
						
		return PBOCUtil.appendTLV((short)0x80, gpo, (short)0x00, (short)gpo.length, apduBuf, (short)0x00);
	}
	
	/**
	 * GPO command process
	 * @param apdu apdu
	 */
	private void onGPO(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x80) {			
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check P1 && P2
		if (apduBuf[ISO7816.OFFSET_P1] != 0x00
			|| apduBuf[ISO7816.OFFSET_P2] != 0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		// check P3
		short p3 = (short)(apduBuf[ISO7816.OFFSET_LC]&0x0FF);
						
		short sPDOLValueLen;
		if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL]) {			
			sPDOLValueLen = (short)(paramBuf[PBOC_PARAM_OFF_QPBOCPDOLVALUE_LEN]&0x0FF);
		} else {			
			sPDOLValueLen = (short)(paramBuf[PBOC_PARAM_OFF_PBOCPDOLVALUE_LEN]&0x0FF);
		}			
				
		short tmp = sPDOLValueLen;
		if (tmp > 0x7F) {
			tmp++;
		}
		tmp += 0x02;
		
		if (p3 != tmp) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		// trade flow check
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] != TRADE_STATE_APP_SELECT) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}		
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] = TRADE_STATE_APP_INIT;
		
		// receive data
		apdu.setIncomingAndReceive();
		
		if (apduBuf[ISO7816.OFFSET_CDATA] != (byte)0x83) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}		
		
		// check ATC
		short sATC = Util.getShort(cardDataBuf, CARD_DATA_OFF_ATC);
		sATC++;
		if (sATC == (short)0xFFFF) {
			appState = APP_STATE_FOREVER_LOCKED;
			Util.arrayFillNonAtomic(abyPBOCTradeSession, (short)0x00, (short)abyPBOCTradeSession.length, (byte)0x00);			
			
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}		
		Util.setShort(cardDataBuf, CARD_DATA_OFF_ATC, sATC);		
		
		short sOff = (short) (ISO7816.OFFSET_CDATA + 0x01);
		if (apduBuf[sOff++] == (byte)0x81) {
			sOff++;
		}
		
		// copy PDOL Value
		Util.arrayCopyNonAtomic(apduBuf, sOff, pdolValue, (short)0x00, sPDOLValueLen);
				
		short sLen = 0;
		byte tradeType;
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_INTERFACE] == TRADE_INTERFACE_CONTACT) {
			tradeType = TRADE_TYPE_PBOC;			
			if (isECTrade(true)) {
				tradeType = TRADE_TYPE_EC;
			}
						
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] = tradeType;	
			
			sLen = PBOCGPOProcess(apduBuf);
		} else {			
			// 终端支持非接触PBOC？卡片采用PBOC交易路径是非接触式PBOC			
			if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_CONTACTLESS_PBOC)) {
				tradeType = TRADE_TYPE_PBOC;				
				
				if (isECTrade(false)) {
					tradeType = TRADE_TYPE_EC;
				}				
				
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] = tradeType;	
				
				sLen = PBOCGPOProcess(apduBuf);
			} else if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_QPBOC)) {
				// 终端支持qPBOC？卡片采用qPBOC交易路径是qPBOC								
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] = TRADE_TYPE_QPBOC;				
								
				if (sQPDOLCAPPIndicateOff != INVALID_VALUE) {
					// FORT BCTC testcase PRSS001 DF60 == 0x04
					if (pdolValue[sQPDOLCAPPIndicateOff] <= EXTEND_APP_TRADE_TYPE_OPC) {					
						abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_TYPE] = pdolValue[sQPDOLCAPPIndicateOff];
						// get DF61
						abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE] = contactlessfci[sExtAppIndicateOff];						
					}
				}
								
				sLen = qPBOCGPOProcess(apduBuf);
			} else {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		}
		
		apdu.setOutgoingAndSend((short)0x00, sLen);
	}
	
	/**
	 * read trade log file
	 * @param sfi		read file sfi
	 * @param logFile	log file buffer
	 * @param recNo		read record no
	 * @param buf		read buffer
	 * @return			read length
	 */
	private short readTradeLog(byte sfi, byte[] logFile, short recNo, byte[] buf) {				
		// 1. dest file is not log file
		// 2. dest record no overflow file record number
		if (logFile == null
			|| (logFile[LOG_INFO_OFF_SFI] != sfi)
			|| (recNo == 0x00)
			|| (recNo > (short)(logFile[LOG_INFO_OFF_RECNUM]&0x0FF))) {
			return 0x00;
		}
		
		short sRecLen = Util.getShort(logFile, LOG_INFO_OFF_RECLEN);
		short sRecNum = (short)(logFile[LOG_INFO_OFF_RECNUM]&0x0FF);
		short fileSize = (short)((short)(sRecLen*sRecNum) + LOG_INFO_OFF_CONTENT);
		short sOffset = LOG_INFO_OFF_CONTENT;
		short sDstOffset = LOG_INFO_OFF_CONTENT;
		while (sOffset < fileSize) {
			if (PBOCUtil.arrayCompare(logFile, sOffset, logFile, sDstOffset, (short)0x04) == 1) {
				sDstOffset = sOffset;
			}
			
			sOffset += sRecLen;
		}
		
	    // 1. log file is empty
	    // 2. read record number > valid record number
		Util.arrayFillNonAtomic(buf, (short)0x00, (short)0x04, (byte)0x00);
		Util.setShort(buf, (short)0x02, recNo);
		if (PBOCUtil.isAllZero(logFile, sDstOffset, (short)0x04)
			|| (PBOCUtil.arrayCompare(buf, (short)0x00, logFile, sDstOffset, (short)0x04) == 0x01)) {
			return 0x00;
		}
		
		short sTmp = (short)((short)(recNo-0x01)*sRecLen);
		if ((short)(sTmp+LOG_INFO_OFF_CONTENT) > sDstOffset) {
			sDstOffset += (short)(fileSize-LOG_INFO_OFF_CONTENT);
		}
		
		sDstOffset = (short)(sDstOffset-sTmp+0x04);
		sRecLen -= 0x04;
		
		Util.arrayCopyNonAtomic(logFile, sDstOffset, buf, (short)0x00, sRecLen);
				
		return sRecLen;
	}	
	
	/**
	 * read charge log file
	 * @param sfi		read file sfi
	 * @param recNo		read record no
	 * @param buf		read buffer
	 * @return			read length
	 */
	private short readChargeLog(byte sfi, short recNo, byte[] buf) {
		// 1. dest file is not log file
		// 2. dest record no overflow file record number
		if ((chargeLogFile == null)
			|| (chargeLogFile[LOG_INFO_OFF_SFI] != sfi)
			|| (recNo > (short)(chargeLogFile[LOG_INFO_OFF_RECNUM]&0x0FF))) {
			return 0x00;
		}
		
		// find first record
		short sRecLen = Util.getShort(chargeLogFile, LOG_INFO_OFF_RECLEN);
		short fileSize = (short) chargeLogFile.length;
		short sOffset = LOG_INFO_OFF_CONTENT;
		short sDstOffset = LOG_INFO_OFF_CONTENT;
		while (sOffset < fileSize) {
			if (PBOCUtil.arrayCompare(chargeLogFile, sOffset, chargeLogFile, sDstOffset, (short)0x04) == 1) {
				sDstOffset = sOffset;
			}
			
			sOffset += sRecLen;
		}
	
		short sLen;
		if (recNo == 0x00) {
	        // P1=00时读圈存日志响应的报文数据域 
	        // 应用交易计数器（ATC） 2 byte
	        // 后续日志记录数        1 byte
	        // 实际日志数据          var byte
	        // 日志完整性验证码      4 byte
			byte recCntr = 0x00;
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, buf, (short)0x00, (short)0x02);
			
			short logFromatLen = (short)chargelogFormat.length;
			short sDateOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_DATE, chargelogFormat, (short)0x00, logFromatLen);
			short sTimeOff = PBOCUtil.findValuePosInTLList(TAG_TRADE_TIME, chargelogFormat, (short)0x00, logFromatLen);
			short sATCOff = PBOCUtil.findValuePosInTLList(TAG_ATC, chargelogFormat, (short)0x00, logFromatLen);
			
			// 最多返回最近10*22个字节的日志数据内容
			short sRecNum = (short)(chargeLogFile[LOG_INFO_OFF_RECNUM]&0x0FF);			
			sLen = 0x03;								
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x04, (byte)0x00);
			for (short i=0x00; (i<sRecNum) && (recCntr<10); i++) {				
				Util.setShort(sessionKey, (short)0x02, i);
				if (PBOCUtil.arrayCompare(sessionKey, (short)0x00, chargeLogFile, sDstOffset, (short)0x04) >= 0x00) {
					break;
				}
				
				short sTmp = (short)(i*sRecLen);
				if ((short)(sTmp+LOG_INFO_OFF_CONTENT) > sDstOffset) {
					sTmp = (short)(fileSize-LOG_INFO_OFF_CONTENT+sDstOffset-sTmp);
				} else {
					sTmp = (short)(sDstOffset-sTmp);
				}				
				
	            // 实际日志数据:
	            //      Put Data命令的P1值（取值为0x9F或0xDF）  1 byte
	            //      Put Data命令的P2值（取值为0x79）        1 byte
	            //      Put Data修改前9F79或DF79的值            6 byte
	            //      Put Data修改后9F79或DF79的值            6 byte
	            //      交易日期                                3 byte
	            //      交易时间                                3 byte
	            //      应用交易计数器（ATC）                   2 byte
				sLen = Util.arrayCopyNonAtomic(chargeLogFile, (short)(sTmp+0x04), buf, sLen, (short)14);
				sLen = Util.arrayCopyNonAtomic(chargeLogFile, (short)(sTmp+0x04+14+sDateOff), buf, sLen, (short)3);
				sLen = Util.arrayCopyNonAtomic(chargeLogFile, (short)(sTmp+0x04+14+sTimeOff), buf, sLen, (short)3);
				sLen = Util.arrayCopyNonAtomic(chargeLogFile, (short)(sTmp+0x04+14+sATCOff), buf, sLen, (short)2);
				
				recCntr++;
			}
			
			buf[0x02] = recCntr;
			
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);
			Util.arrayCopyNonAtomic(sessionKey, (short)0x06, sessionKey, (short)14, (short)0x02);
			sessionKey[14] ^= (byte)0xFF;
			sessionKey[15] ^= (byte)0xFF;
			
			// generate MAC Session Key
			tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_MAC_KEY);
			cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
			
			tripleDesKey.setKey(sessionKey, (short)0x00);
			signMac.sign(buf, (short) 0, sLen, buf, sLen);
			sLen += 0x04;			
		} else {
		    // 1. log file is empty
		    // 2. read record number > valid record number
			Util.arrayFillNonAtomic(buf, (short)0x00, (short)0x04, (byte)0x00);
			Util.setShort(buf, (short)0x02, recNo);
			if (PBOCUtil.isAllZero(chargeLogFile, sDstOffset, (short)0x04)
				|| (PBOCUtil.arrayCompare(buf, (short)0x00, chargeLogFile, sDstOffset, (short)0x04) == 0x01)) {
				return 0x00;
			}
			
			short sTmp = (short)((short)(recNo-0x01)*sRecLen);
			if ((short)(sTmp+LOG_INFO_OFF_CONTENT) > sDstOffset) {
				sDstOffset += (short)(fileSize-LOG_INFO_OFF_CONTENT);
			}
			
			sDstOffset = (short)(sDstOffset-sTmp+0x04);
			sLen = (short)(sRecLen-0x04);
			
			Util.arrayCopyNonAtomic(chargeLogFile, sDstOffset, buf, (short)0x00, sLen);
		}
		
		return sLen;
	}
	
	/**
	 * read record command process
	 * @param apdu apdu
	 */
	private void onReadRecord(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != 0x00) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		byte sfi = (byte)((byte)(apduBuf[ISO7816.OFFSET_P2]>>0x03)&0x1F);
		byte recNo = apduBuf[ISO7816.OFFSET_P1];
		
		short dgi = Util.makeShort(sfi, recNo);
		
		short index;
		short sTmp = 0x00;
		for (index=0x00; index<RECORD_OBJECT_SIZE; index++) {
			sTmp = recordMap[index];
			
			if (sTmp == INVALID_RECORD_MAP_VALUE) {
				break;
			}
			
			if (sTmp == dgi) {				
				break;
			}			
		}
		
		if (sTmp != dgi) {
			// try read trade log file
			short sLen = readTradeLog(sfi, tradeLogFile, (short)(recNo&0x0FF), apduBuf);
			
			// try read charge log file
			if (sLen == 0x00) {				
				sLen = readChargeLog(sfi, (short)(recNo&0x0FF), apduBuf);								
			}
			
			// try read extend application trade log file
			if (sLen == 0x00) {
				sLen = readTradeLog(sfi, extendlogFile, (short)(recNo&0x0FF), apduBuf);
//				if (sLen != 0x00) {
//					abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI] = sfi;
//					Util.arrayFillNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_CUR_ID, (short)0x02, (byte)0x00);
//				}
			}

			if (sLen == 0x00) {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);	
			}
									
			apdu.setOutgoingAndSend((short)0x00, sLen);
			return;
		}
		
		byte[] record = (byte[])recordObj[index];
		short sLen = (short)record.length;
		
		Util.arrayCopyNonAtomic(record, (short)0x00, apduBuf, (short)0x00, sLen);
		sLen = apduBuf[0x01];
		if (sLen == (byte)0x81) {
			sLen = (short)(apduBuf[0x02]&0x0FF);
			sLen += 0x03;
		} else {
			sLen += 0x02;
		}
		boolean bBack = true;
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] == TRADE_TYPE_QPBOC) {
			if (dgi == sQPBOCSigDGI) {
				// if read 9F4B DDA
				short sDDALen = (short)ddaTemplate.length;				
				Util.arrayCopyNonAtomic(ddaTemplate, (short)0x00, apduBuf, sQPBOCSigOff, sDDALen);
				Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, (short)(sQPBOCSigOff+DDA_OFF_IC_DATA_DIGIT), (short)0x02);
				
				msgDigest.update(apduBuf, (short)(sQPBOCSigOff+DDA_OFF_SIGN_FORMAT), (short)(sDDALen-22));
				
				if (PBOCUtil.isBitSet(pdolValue, sQPDOLVTerminalTradeAttrOff, TER_TRADE_ATT_OFF_SUPPORT_FDDA_VERSION) && bIsPBOC3) {
					// fDDA version 00 用于输入DDA哈希算法的终端动态数据
					// 标签 数据元素 				长度 	数据来源
					// 9F37 不可预知数			4字节	终端
					// 9F02 授权金额 				6字节 	终端
					// 5F2A 交易货币代码 			2字节 	终端
					// 9F69 卡片认证相关数据 		可变 	卡片 (12部分附录C 注：在本版本规范中，卡片认证相关数据使用8个字节长度，并且被个人化到卡片中。)
					// 9F36 应用交易计数器（ATC） 	2字节	卡片
					msgDigest.update(pdolValue, sQPDOLTerminalTradeRandomOff, (short)0x04);
					msgDigest.update(pdolValue, sQPDOLTradeAuthMoneyOff, (short)0x06);
					msgDigest.update(pdolValue, sQPDOLTradeCoinCodeOff, (short)0x02);
					
					// update 卡片认证相关数据
					abyCurTradeCardData[CARD_DATA_OFF_CARD_AUTH_DATA] = 0x01;
					random.generateData(abyCurTradeCardData, (short)(CARD_DATA_OFF_CARD_AUTH_DATA+0x01), (short)0x04);
					Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE, abyCurTradeCardData, (short)(CARD_DATA_OFF_CARD_AUTH_DATA+0x05), (short)0x02);
					
			        // 第14部分 5.2.6 结束处理
			        // 如果卡片的fDDA版本号为“01”，则卡片在产生动态签名前应将分段扣费应用标识（DF61）
			        // 的值动态填充到卡片认证相关数据（9F69）的第8个字节中再进行动态签名的运算。
					abyCurTradeCardData[(short)(CARD_DATA_OFF_CARD_AUTH_DATA+0x07)] = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE];
					
					msgDigest.doFinal(abyCurTradeCardData, CARD_DATA_OFF_CARD_AUTH_DATA, (short)0x08, apduBuf, (short)(sQPBOCSigOff+sDDALen-21));										
				} else {
					abyCurTradeCardData[CARD_DATA_OFF_CARD_AUTH_DATA] = 0x00;
					// fDDA version 00 用于输入DDA哈希算法的终端动态数据
					// 标签 数据元素 				长度 	数据来源
					// 9F37 不可预知数			4字节	终端
					// 9F36 应用交易计数器（ATC） 	2字节	卡片
					msgDigest.doFinal(pdolValue, sQPDOLTerminalTradeRandomOff, (short)0x04, apduBuf, (short)(sQPBOCSigOff+sDDALen-21));
				}

				cipherRSA.doFinal(apduBuf, sQPBOCSigOff, sDDALen, apduBuf, sQPBOCSigOff);				
			} 
			
			if (dgi == sQPBOC9F5DDGI) {
				// if read 9F5D
				Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, apduBuf, sQPBOC9F5DOff, (short)0x06);
				Util.arrayCopy(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, cardDataBuf, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06);
			}
			
			// read last record, update trade data
			if (dgi == sQPBOCLastRecDGI) {				
				JCSystem.beginTransaction();
				
				if (isCPPQPBOCSupportTradeLog) {
					// record QPBOC trade log
					updateTradeLog(logTemplate_5, apduBuf);
					Util.arrayCopyNonAtomic(record, (short)0x00, apduBuf, (short)0x00, sLen);
				}

				// 非接触面，读取最后一条记录，上笔或者当前交易做了fDDA 01则将9F69在最后一条记录中返回
				if (abyCurTradeCardData[CARD_DATA_OFF_CARD_AUTH_DATA] == 0x01) {
					// 若qPBOC执行的是01 fDDA, 则9F69(卡片认证相关数据)需要在最后一条记录中返回
					sLen = PBOCUtil.appendTLV(TAG_CARD_AUTH_DATA, abyCurTradeCardData, CARD_DATA_OFF_CARD_AUTH_DATA, (short)0x08, apduBuf, sLen);
					if (apduBuf[0x01] == (byte)0x81) {
						apduBuf[0x02] = (byte)(sLen-0x03);
					} else {
						sTmp = (short)((sLen-0x02));
						apduBuf[0x01] = (byte)sTmp;				 
						if (sTmp > 0x7F) {
							sLen = Util.arrayCopyNonAtomic(apduBuf, (short)0x02, apduBuf, (short)0x03, sTmp);
							apduBuf[0x01] = (byte)0x81;
						}
					}	
				}
				
				byte extTradeType = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_TYPE];
				if (extTradeType != EXTEND_APP_TRADE_TYPE_NOT_SUPPORT) {
					if (!curTradeConditions[CURRENT_TRADE_CONDITION_OFF_EXT_TRADE_RESULT]) {
						ISOException.throwIt((short)0x6974);
					}
					
					Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO, (short)0x0A, (byte)0x00);
					Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, abyCurTradeCardData, CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO, (short)0x02);
					
                    // 第14部分 A.4 GETTRANSPROVE（取脱机交易应用密文）命令
                    // 如果最近一笔交易是脱机预授权交易，则返回的TC为全零
					if (extTradeType != EXTEND_APP_TRADE_TYPE_OP) {
						Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC, abyCurTradeCardData, (short)(CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO+0x02), (short)0x08);
					}
					
					flushCacheData();
					
					if (extTradeType == EXTEND_APP_TRADE_TYPE_OP) {
						// 设置预付费交易预授权金额
						short extPreAuthOff = Util.getShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_CUR_CONTEXT_OFF);
						extendPreAuthContext[(short)(extPreAuthOff+EXT_PREAUTH_CONTEXT_OFF_SFI)] = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI];
						Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_CUR_ID, extendPreAuthContext, (short)(extPreAuthOff+EXT_PREAUTH_CONTEXT_OFF_ID), (short)0x02);
						Util.arrayCopyNonAtomic(pdolValue, sQPDOLTradeAuthMoneyOff, extendPreAuthContext, (short)(extPreAuthOff+EXT_PREAUTH_CONTEXT_OFF_MONEY), (short)0x06);
					} else if (extTradeType == EXTEND_APP_TRADE_TYPE_OPC) {
						Util.arrayFillNonAtomic(extendPreAuthContext, Util.getShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_CUR_CONTEXT_OFF), EXT_PREAUTH_CONTEXT_ITEM_LEN, (byte)0x00);
					}					
				}
								
				// update QPBOC trade data
				Util.arrayCopy(abyCurTradeCardData, CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO, cardDataBuf, CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO, (short)(CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY-CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO));
				
				// backup last record
				Util.arrayCopy(apduBuf, (short)0x00, apduBuf, (short)0x02, sLen);
				Util.setShort(apduBuf, (short)0x00, sLen);
				Util.arrayCopy(apduBuf, (short)0x00, backRecord, (short)0x00, (short)(sLen+0x02));
				Util.arrayCopy(apduBuf, (short)0x02, apduBuf, (short)0x00, sLen);
				
				JCSystem.commitTransaction();
				
				bBack = false;
			}
		}
		
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] == TRADE_STATE_APP_SELECT) {
			short sOff = 0x01;
			short sValueLen = (short)(apduBuf[sOff++]&0x0FF);
			if (sValueLen == (short)0x81) {
				sValueLen = (short)(apduBuf[sOff++]&0x0FF);
			}
			
			// process 9F5D
			sTmp = PBOCUtil.findValueOffByTag(TAG_AVAILABLE_OFFLINE_MONEY, apduBuf, sOff, sValueLen);
			if (sTmp != PBOCUtil.TAG_NOT_FOUND) {
				calAvailableMoney();
				
				sTmp += (short)(sOff + 0x03);
				if (Util.arrayCompare(apduBuf, sTmp, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06) != 0x00) {
					Util.arrayCopyNonAtomic(apduBuf, sTmp, abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)0x06);
				}												
			}
			
			// find 9F4B
			sTmp = PBOCUtil.findValueOffByTag(TAG_SIGN_DYNAMIC_APP_DATA, apduBuf, sOff, sValueLen);
			if (sTmp != PBOCUtil.TAG_NOT_FOUND) {
				sTmp += (short)(sOff + 0x02);
				sValueLen = (short) (apduBuf[(short)(sTmp+0x01)]&0x0FF);
				if (PBOCUtil.isAllZero(apduBuf, (short)(sTmp+0x02), sValueLen)) {
					apduBuf[sTmp] = 0x00;
					
					// exist other TLV
					short remainLen = (short)(sLen-sTmp-sValueLen-0x02);
					if (remainLen > 0x00) {
						Util.arrayCopyNonAtomic(apduBuf, (short)(sTmp+0x02+sValueLen), apduBuf, (short)(sTmp+0x01), remainLen);
					}
					
					sLen = (short)(sLen-sValueLen-0x01);
					sValueLen = (short)(sLen-0x03);
					if (sValueLen < 0x80) {
						Util.arrayCopyNonAtomic(apduBuf, (short)0x03, apduBuf, (short)0x02, sValueLen);
						apduBuf[0x01] = (byte)sValueLen;
					} else {
						apduBuf[0x02] = (byte)sValueLen;
					}
				}
			}
		}
		
		// get back response data length
		sTmp = Util.getShort(backRecord, (short)0x00);
		if ((dgi == sQPBOCLastRecDGI) && bBack && (sTmp != 0x00)) {
			sLen = sTmp;
			Util.arrayCopy(backRecord, (short)0x02, apduBuf, (short)0x00, sLen);
		}
		
		apdu.setOutgoingAndSend((short)0x00, sLen);
	}
	
	/**
	 * get data command process
	 * @param apdu	apdu
	 */
	private void onGetData(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x80) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		short sTag = Util.getShort(apduBuf, ISO7816.OFFSET_P1);
		short index = 0x00;
		
		while (true) {
			short sTmp = getDataTags[index];
			if (sTmp == sTag) {
				break;
			} 
			
			if (sTmp == INVALID_VALUE) {
				ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
			}
			
			index += 0x03;
		}
		
		index++;
		short sLen = 0;		
		switch (sTag) {
		// PIN Retry counter
		case TAG_PIN_RETRY_CNTR:
			sLen = PBOCUtil.appendTLV(sTag, paramBuf, PBOC_PARAM_OFF_PIN_LEFT_CNTR, (short)0x01, apduBuf, (short)0x00);
			break;
		case TAG_AVAILABLE_OFFLINE_MONEY:
			// 可用脱机余额0x9F5D，在卡片附加处理“返回可用脱机余额”置位时才返回
//			if (isCPPReturnAvailableMoney) {
				calAvailableMoney();
				sLen = PBOCUtil.appendTLV(sTag, abyCurTradeCardData, getDataTags[index], (short)0x06, apduBuf, (short)0x00);
//			} else {
//				ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
//			}			
			break;
		case TAG_LOG_FORMAT:
			if (logFormat == null) {
				Util.setShort(apduBuf, (short)0x00, TAG_LOG_FORMAT);
				apduBuf[0x02] = 0x00;
				sLen = 0x03;
			} else {
				sLen = PBOCUtil.appendTLV(sTag, logFormat, (short)0x00, (short)logFormat.length, apduBuf, (short)0x00);
			}
			break;
		case TAG_CHARGE_LOG_FORMAT:
			if (chargelogFormat == null) {
				Util.setShort(apduBuf, (short)0x00, TAG_LOG_FORMAT);
				apduBuf[0x02] = 0x00;
				sLen = 0x03;
			} else {
				sLen = PBOCUtil.appendTLV(sTag, chargelogFormat, (short)0x00, (short)chargelogFormat.length, apduBuf, (short)0x00);
			}
			break;			
		case TAG_CAPP_SECTION_PURCHASE_APP_ID:
			if (sExtAppIndicateOff != INVALID_VALUE) {
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE] = contactlessfci[sExtAppIndicateOff];
			}
			
			sLen = PBOCUtil.appendTLV(sTag, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE, (short)0x01, apduBuf, (short)0x00);			
			break;
		case TAG_GET_APP_VERSION:
			sLen = PBOCUtil.appendTLV(sTag, app_version, (short)0x00, (short)app_version.length, apduBuf, (short)0x00);
			break;
		case TAG_GET_APP_NAME:
			sLen = PBOCUtil.appendTLV(sTag, app_name, (short)0x00, (short)app_name.length, apduBuf, (short)0x00);
			break;
		default:
			short sOff = getDataTags[index++];
			short sValueLen = getDataTags[index];
			// LV Struct
			if (sValueLen == INVALID_VALUE) {				
				sValueLen = cardDataBuf[sOff++];
			}

			byte[] src;
			if (sOff >= (short)abyCurTradeCardData.length) {
				src = cardDataBuf;
			} else {
				src = abyCurTradeCardData;
			}
			
			if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE]) {
				switch (sTag) {
				// 当终端以 GET DATA 命令读取电子现金余额（标签“9F79”）时，卡片应将第二币种电子现金余额（标签“DF79”）的值返回
				case TAG_EC_BALANCE:
					sOff = CARD_DATA_OFF_EC_SECOND_BALANCE;
					break;
				// 当终端以 GET DATA 命令读取电子现金重置阈值（标签“9F6D”）时，卡片应将第二币种电子现金重置阈值（标签“DF76”）的值返回
				case TAG_EC_RESET_THRESHOLD:
					sOff = CARD_DATA_OFF_EC_SECOND_RESET_THRESHOLD;
					break;
				// 当终端以 GET DATA 命令读取电子现金余额上限（标签“9F77”）时，卡片应将第二币种电子现金余额上限（标签“DF77”）的值返回
				case TAG_EC_BALANCE_LIMIT:
					sOff = CARD_DATA_OFF_EC_SECOND_BALANCE_LIMIE;
					break;
				// 当终端以 GET DATA 命令读取电子现金单笔交易限额（标签“9F78”）时，卡片应将第二币种电子现金单笔交易限额（标签“DF78”）的值返回
				case TAG_SINGLE_TRADE_LIMIT:
					sOff = CARD_DATA_OFF_EC_SECOND_SINGLE_TRADE_LIMIT;
					break;
				// 当终端以 GET DATA 命令读取卡片 CVM 限额（标签“9F6B”）时，卡片应将第二币种卡片 CVM限额（标签“DF72”）的值返回
				case TAG_CARD_CVM_LIMIT:
					sOff = CARD_DATA_OFF_EC_SECOND_CVM_LIMIT;
					break;
				}
			}
			
			sLen = PBOCUtil.appendTLV(sTag, src, sOff, sValueLen, apduBuf, (short)0x00);			
		}

		apdu.setOutgoingAndSend((short)0x00, sLen);
	}
	
	/**
	 * EC trade check
	 * @param acType				AC type
	 * @param abyCurTradeCDOL		CDOL
	 * @param abyCurTradeCDOLValue	CDOL Value
	 * @param abyCurTradePDOL		PDOL
	 * @return true check success, false check failed
	 */
	private boolean ecGACCheck(byte acType, byte[] abyCurTradeCDOL, byte[] abyCurTradeCDOLValue, byte[] abyCurTradePDOL) {
	    // 第13部分 7.4.5  卡片行为分析 
	    /*
	     * 若终端请求脱机批准，则卡片应检查终端在GENERATE AC命令中给出的标签的值与GPO命令
	     * 中给出的标签的值是否一致（这些标签包括但不仅限于交易货币代码‘5F2A’、授权金额‘9F02’，
	     * 但不包括终端验证结果‘95’，交易状态信息‘9B’和不可预知数‘9F37’）。如果检查的结
	     * 果为一致，则卡片从电子现金余额中扣除授权金额并在GENERATE AC命令响应中返回TC，否
	     * 则卡片在GENERATE AC命令响应中返回AAC； 
	    */
		if (acType != GENERATE_AC_TYPE_TC) {
			return true;
		}
		
		short i = 0x00;
		short sCDOLLen = (short)abyCurTradeCDOL.length;
		short sPDOLLen = (short)abyCurTradePDOL.length;
		short sTag;
		while (i < sCDOLLen) {
			sTag = (short) (abyCurTradeCDOL[i++]&0x00FF);
			if ((short)(sTag&0x01F) == 0x01F) {
				sTag <<= 0x08;
				sTag |= (short) (abyCurTradeCDOL[i++]&0x0FF);
			}

			// get value length
			short sValueLen = (short) (abyCurTradeCDOL[i++]&0x0FF);
			
			if ((sTag == TAG_TVR)
				|| (sTag == TAG_TRADE_STATE_INFO)
				|| ((sTag == TAG_TERMINAL_TRADE_RANDOM))) {
				continue;
			}
			
			short sPDOLOff = PBOCUtil.findValuePosInTLList(sTag, abyCurTradePDOL, (short)0x00, sPDOLLen);
			if (sPDOLOff != PBOCUtil.TAG_NOT_FOUND) {
				short sCDOLOff = PBOCUtil.findValuePosInTLList(sTag, abyCurTradeCDOL, (short)0x00, sCDOLLen);
				if ((sCDOLOff != PBOCUtil.TAG_NOT_FOUND)
					&& (Util.arrayCompare(pdolValue, sPDOLOff, abyCurTradeCDOLValue, sCDOLOff, sValueLen) != 0x00)) {
					return false;
				}
			}			
		}
				
		return true;
	}
	
	/**
	 * generate AC card risk manager
	 * @param acType			AC type
	 * @param abyCurTradePDOL	PDOL
	 * @param tmpBuf			temp buffer
	 * @return trade result
	 */
	private byte cardRiskManager_1(byte acType, byte[] abyCurTradePDOL, byte[] tmpBuf) {
		/**
		 * 3. 上次交易静态数据认证（SDA）失败检查
		 * 如果支持SDA，此检查必备执行。检查上次脱机拒绝的交易中SDA是否失败。
		 * 如果SDA失败指示位为“1”，卡片设置CVR中“上次交易SDA失败而且交易拒绝”位为“1”。
		 */
		if (PBOCUtil.isBitSet(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, AIP_SUPPORT_OFF_SDA)
			&& (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_REFUSE_SDA_FAILED] == 0x01)) {
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_LAST_TRADE_REFUSE_SDA_FAILED);
		}
		
		/**
		 * 4. 上次交易动态数据认证（DDA）失败检查
		 * 如果支持DDA，此检查强制执行。检查上次脱机拒绝的交易中DDA是否失败。
		 * 如果DDA失败指示位为“1”，卡片设置CVR中“上次交易DDA失败而且交易拒绝”位为“1”。
		 */
		if (PBOCUtil.isBitSet(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, AIP_SUPPORT_OFF_DDA)
			&& (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_REFUSE_DDA_FAILED] == 0x01)) {
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_LAST_TRADE_REFUSE_DDA_FAILED);
		}
		
		/**
		 * 若是电子现金应用
		 * 跳过联机授权未完成检查、上次交易发卡行认证失败检查、上次联机交易发卡行脚本处理检查、
		 * 新卡检查、脱机 PIN 尝试次数检查及各类频度检查，
		 * 进行上次交易 SDA 失败检查和上次交易 DDA 失败检查；
		 */
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] == TRADE_TYPE_EC) {
			if (!ecGACCheck(acType, cdol1, cdol1Value, abyCurTradePDOL)) {				
				return TRADE_RESULT_AAC;
			}
			
			return TRADE_RESULT_TC;
		}
		
		short tradeAuthMoneyOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY]&0x0FF);
		short tradeCoinCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_COIN_CODE]&0x0FF);
		byte tradeResult = TRADE_RESULT_TC;
		
		/**
		 * 1. 联机授权没有完成检查
		 * 如果支持发卡行认证或发卡行脚本命令，需要执行此检查
		 * 检查在上次交易中，在卡片请求一个联机授权之后，在终端接收到联机响应进行处理之前或无法联机的终端处理之前，卡片是否离开了终端设备
		 * 如果联机授权指示位设为“1”，卡片：
		 * 设置卡片请求联机指示位置“1”
		 * 设置 CVR 中“上次联机交易没完成”位为“1”
		 */
		if (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ONLINE_AUTH] == 0x01) {			
			tradeResult = TRADE_RESULT_ARQC;
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_LAST_ONLINE_TRADE_UNFINISHED);
		}
			
		/**
		 * 2. 上次交易发卡行认证失败（或必备未执行）检查
		 * 如果卡片AIP中表明支持发卡行认证，则应执行此检查。
		 * 如果上次交易发卡行认证（1）失败或（2）必备（发卡行认证指示位表示）但是没有执行，卡片请求联机处理。 
		 * 如果发卡行认证失败指示位设为“1”，卡片：
		 * 设置 CVR 中“上次联机交易发卡行认证失败”位为“1”； 
		 * 如果应用缺省行为（ADA）中“发卡行认证失败，下次交易联机上送”位为“1”，设置卡片请求联机指示位置“1”。
		 */
		if (PBOCUtil.isBitSet(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, AIP_SUPPORT_OFF_ISSUE_AUTH)
			&& (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] == 0x01)) {
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_LAST_ONLINE_TRADE_ISSUE_AUTH_FAILED);
			if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_ISSUE_AUTH_FAILED)) {				
				tradeResult = TRADE_RESULT_ARQC;
			}
		}
		
		/**
		 * 5. 上次联机交易发卡行脚本处理检查
		 * 如果支持发卡行脚本处理，此检查强制执行。使用上次联机交易处理的发卡行脚本命令计数器和脚本处理失败指示位数据元。 
		 * 卡片设置CVR中第4字节的第8-5位为发卡行脚本命令计数器的值。 
		 * 如果发卡行脚本失败指示位为“1”，卡片设置CVR中“上次交易发卡行脚本处理失败”位为“1”。
		 * 如果发卡行脚本失败指示位为“1”，如果ADA中“如果上次交易发卡行脚本失败，交易联机上送”位是“1”，设置卡片请求联机指示位为“1”。
		 */
		abyPBOCTradeSession[(short)(TRADE_SESSION_DATA_OFF_CVR+0x02)] = (byte)((byte)(abyPBOCTradeSession[(short)(TRADE_SESSION_DATA_OFF_CVR+0x02)]&0x0F) | (byte)(abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR]<<0x04));
		if (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] == 0x01) {
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_LAST_TRADE_ISSUE_SCRIPT_FAILED);
			if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_LAST_TRADE_ISSUE_SCRIPT_FAILED)) {				
				tradeResult = TRADE_RESULT_ARQC;
			}
		}
		
		/**
		 * 6. 连续脱机交易下限频度检查
		 * 此检查可选。如果连续脱机交易次数超过此下限，卡片请求联机授权。 
		 * 如果上次联机ATC寄存器和JR/T  0025专有数据：连续脱机交易下限（标签“9F58”）存在，卡片可以执行此检查。 
		 * 如果ATC和上次联机ATC寄存器的差值大于连续脱机交易下限，卡片：
		 * 设置 CVR 中“频度检查超过”位为“1”
		 * 设置卡片请求联机指示位为“1”。在卡片风险管理结束时，卡片返回联机请求
		 */
		// T06_VLT004 test case 9F58 Data Value is 0x00
		if (cardDataBuf[CARD_DATA_OFF_OFFLINE_CARD_LOWLIMIT] != (byte)0xFF) {
			short sPreOnlineATC = Util.getShort(abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC);
			short sATC = Util.getShort(cardDataBuf, CARD_DATA_OFF_ATC);
			
			sPreOnlineATC += (short)(cardDataBuf[CARD_DATA_OFF_OFFLINE_CARD_LOWLIMIT]&0x0FF);
			if (sATC > sPreOnlineATC) {
				PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
				tradeResult = TRADE_RESULT_ARQC;
			}
		}
		
		/**
		 * 7. 连续国际脱机交易（基于货币）限制数频度检查
		 * 此检查可选。如果连续脱机交易计数器（国际-货币）超过连续脱机交易限制数（国际-货币），卡片请求联机授权。
		 * 此检查定义的国际脱机交易是终端发送的交易货币代码和卡片中的应用货币代码不同的交易。
		 * 如果数据应用货币代码、连续脱机交易计数器（国际-货币）、连续脱机交易限制次数（国际-货币）存在，卡片执行此检查。
		 * 卡片比较交易货币代码和应用货币代码，如果不等，而且连续脱机交易计数器（国际-货币）加1的值大于连续脱机交易限制次数（国际-货币），卡片：
		 * 设置 CVR 中“频度检查超过”位为“1”
		 * 设置卡片请求联机指示位为“1”
		 */
		if (cardDataBuf[CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT] != (byte)0xFF) {
			if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, cdol1Value, tradeCoinCodeOff, (short)0x02) != 0x00) {
				if ((short)((short)(abyCurTradeCardData[CARD_DATA_OFF_INTERCOINOFFLINE_ATC]&0x0FF)+0x01) > (short)(cardDataBuf[CARD_DATA_OFF_COIN_OFFLINE_CARD_LIMIT]&0x0FF)) {
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
					tradeResult = TRADE_RESULT_ARQC;
				}
			}
		}
		
		/**
		 * 8. 连续国际脱机交易（基于国家）限制数频度检查
		 * 此检查可选。如果连续脱机交易计数器（国际-国家）超过连续脱机交易限制数（国际-国家），
		 * 卡片请求联机授权。 此检查定义的国际脱机交易是终端送进的终端国家代码和卡片中的发卡行国家代码不同的交易。 
		 * 如果数据发卡行国家代码、连续脱机交易计数器（国际-国家）、连续脱机交易限制次数（国际-国家）存在，卡片执行此检查。 
		 * 如果下面两个条件都满足
		 * 终端国家代码和发卡行国家代码不同
		 * 连续脱机交易计数器（国际-国家）加 1 的值大于连续脱机交易限制次数（国际-国家）
		 * 卡片:
		 * 设置 CVR 中“频度检查超过”位为“1”
		 * 设置卡片请求联机指示位为“1”
		 */
		if (cardDataBuf[CARD_DATA_OFF_STATE_OFFLINE_CARD_LIMIT] != (byte)0xFF) {
			if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_ISSUE_STATE_CODE, cdol1Value, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TERMINAL_STATE_CODE]&0x0FF), (short)0x02) != 0x00) {
				if ((short)((short)(abyCurTradeCardData[CARD_DATA_OFF_INTERSTATEOFFLINE_ATC]&0x0FF)+0x01) > (short)(cardDataBuf[CARD_DATA_OFF_STATE_OFFLINE_CARD_LIMIT]&0x0FF)) {
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
					tradeResult = TRADE_RESULT_ARQC;
				}
			}
		}
		
		/**
		 * 9. 使用指定货币的脱机交易累计金额频度检查
		 * 此检查可选。如果使用应用指定货币的累计脱机交易金额超过累计脱机交易金额限制，卡片请求联机授权。 
		 * 如果数据应用货币代码、累计脱机交易金额、累计脱机交易金额限制存在，卡片执行此检查。 
		 * 如果下面两个条件都满足： 
		 * ——交易货币代码等于应用货币代码； 
		 * ——累计脱机交易金额加本次授权金额大于累计脱机交易金额限制。 
		 * 卡片： 
		 * ——设置 CVR 中“频度检查超过”位为“1”； 
		 * ——设置卡片请求联机指示位为“1”。
		 */
		if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, cdol1Value, tradeCoinCodeOff, (short)0x02) == 0x00) {
			if (!PBOCUtil.isAllZero(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT, (short)0x06)) {
				PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, cdol1Value, tradeAuthMoneyOff, tmpBuf, (short)0x00);				
				if (PBOCUtil.arrayCompare(tmpBuf, (short)0x00, cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_LIMIT, (short)0x06) == 0x01) {
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
					tradeResult = TRADE_RESULT_ARQC;
				}
			}
		}
		
		/**
		 * 10. 交易累计金额（双货币）频度检查
		 * 此检查可选。如果使用应用指定货币和第2应用货币并接受脱机的累计脱机交易金额超过累计脱机交易金额限制（双货币），卡片请求联机授权。 
		 * 如果数据应用货币代码、第2应用货币代码、货币转换因子、累计脱机交易金额（双货币）、累计
		 * 脱机交易金额限制（双货币）存在，卡片执行此检查。 
		 * ——如果交易货币代码等于应用货币代码，累计脱机交易金额（双货币）加本次授权金额和累计脱机交易金额限制（双货币）进行比较； 
		 * ——如果交易货币代码等于第 2 应用货币代码， 使用货币转换因子将授权金额转换为近似的应用货币代码金额。 累计脱机交易金额 （双货币） 加这个近似的授权金额和累计脱机交易金额限制 （双货币）进行比较； 
		 * ——如果比较的结果是大于了限制数，卡片应该采取以下措施： 
		 * ●   设置 CVR 中“频度检查超过”位为“1”； 
		 * ●   设置卡片请求联机指示位为“1”。
		 */
		if (!PBOCUtil.isAllZero(cardDataBuf, CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT, (short)0x06)) {
			if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, cdol1Value, tradeCoinCodeOff, (short)0x02) == 0x00) {
				PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, cdol1Value, tradeAuthMoneyOff, tmpBuf, (short)0x00);				
				if (PBOCUtil.arrayCompare(tmpBuf, (short)0x00, cardDataBuf, CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT, (short)0x06) == 0x01) {
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
					tradeResult = TRADE_RESULT_ARQC;
				}
			} else if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_SECOND_APP_COIN_CODE, cdol1Value, tradeCoinCodeOff, (short)0x02) == 0x00) {
				PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_TRADE_AUTH_NEAR_MONEY, tmpBuf, (short)0x00);				
				if (PBOCUtil.arrayCompare(tmpBuf, (short)0x00, cardDataBuf, CARD_DATA_OFF_DCOIN_TOTAL_CARD_MONEY_LIMIT, (short)0x06) == 0x01) {
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);
					tradeResult = TRADE_RESULT_ARQC;
				}
			}	
		}
		
		/**
		 * 11. 新卡检查
		 * 此检查可选。如果卡片是新卡，交易请求联机。新卡是指从来没有联机接受过的卡片。 如果数据上次联机ATC寄存器、应用缺省行为存在，卡片执行此检查。
		 * 如果上次联机ATC寄存器值为零，卡片应该采取以下措施： 
		 * ——设置 CVR 中“新卡”位为“1”； 
		 * ——如果 ADA 中“如果新卡，交易联机”位为“1”，设置卡片请求联机指示位为“1”。
		 */
		if (PBOCUtil.isAllZero(abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC, (short)0x02)) {
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_NEW_CARD);
			if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_NEW_CARD)) {
				tradeResult = TRADE_RESULT_ARQC;
			}
		}
		
		/**
		 * 12. 脱机PIN验证没有执行（PIN尝试限制数超过）检查
		 * 当卡片支持脱机PIN验证，此检查可选。如果PIN尝试限制数在上次交易中就已超过，交易请求联机或拒绝交易。 
		 * 如果执行此检查，卡片中要有应用缺省行为（ADA）数据。 
		 * 如果下列所有条件成立： 
		 * ——卡片支持脱机 PIN 验证； 
		 * ——卡片没有收到过验证命令； 
		 * ——PIN 尝试计数器已经为零。 
		 * 卡片要执行下列操作： 
		 * ——设置 CVR 中“PIN 尝试限制数超过”位为“1”； 
		 * ——如果 ADA 中“如果上次交易 PIN 尝试限制数超过，交易拒绝”位为“1”，设置卡片请求拒绝指示位为“1”； 
		 * ——如果 ADA 中“如果上次交易 PIN 尝试限制数超过，交易联机”位为“1”，设置卡片请求联机指示位为“1”； 
		 * ——如果 ADA 中“如果上次交易 PIN 尝试限制数超过，交易拒绝并锁应用”位为“1”，拒绝交易并锁应用。
		 */
		if ((paramBuf[PBOC_PARAM_OFF_PIN_MAX_CNTR] != 0x00)			
			&& (paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] == 0x00)
			&& (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR] == 0x00)) {
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_BLOCKED);
			if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_AAC)) {				
				tradeResult = TRADE_RESULT_AAC;
			} else if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_ARQC)) {				
				tradeResult = TRADE_RESULT_ARQC;
			} else if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_AAC_LOCK_APP)) {				
				appState = APP_STATE_LOCKED;
				
				Util.arrayFillNonAtomic(abyPBOCTradeSession, (short)0x00, (short)abyPBOCTradeSession.length, (byte)0x00);					
				
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		}
		
		return tradeResult;
	}
	
	/**
	 * set CID AC Type
	 * @param type AC Type
	 */
	private void setCIDACType(byte type) {
		byte cid = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID];
		
		cid &= (byte)(~CID_AC_TYPE_MASK);
		cid |= (byte)(type&CID_AC_TYPE_MASK);
		
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID] = cid;
	}
	
	/**
	 * set CID reason code
	 * @param reason reason code
	 */
	private void setCIDReasonCode(byte reason) {
		byte cid = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID];
		
		cid &= (byte)(~CID_REASON_CODE_MASK);
		cid |= (byte)(reason&CID_REASON_CODE_MASK);
		
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID] = cid;
	}
		
	/**
	 * record trade log
	 * @param logTemplate			log template
	 * @param abyCurTradeCDOLValue	CDOL
	 * @param tmpBuf				temp buffer
	 */
	private void updateTradeLog(short[] logTemplate, byte[] tmpBuf) {		
		if (logTemplate == null) {
			return;
		}
		short sLogTemplateLen = (short) logTemplate.length;
		
		short sTradeLogLen = 0x04;
		short i = 0x00;
		while (i<sLogTemplateLen) {
			switch (logTemplate[i]) {
			case LOG_VALUE_TYPE_PDOL:
				sTradeLogLen = Util.arrayCopyNonAtomic(pdolValue, logTemplate[(short)(i+0x01)], tmpBuf, sTradeLogLen, logTemplate[(short)(i+0x02)]);
				break;
			case LOG_VALUE_TYPE_CDOL1:
				sTradeLogLen = Util.arrayCopyNonAtomic(cdol1Value, logTemplate[(short)(i+0x01)], tmpBuf, sTradeLogLen, logTemplate[(short)(i+0x02)]);
				break;
			case LOG_VALUE_TYPE_CDOL2:
				sTradeLogLen = Util.arrayCopyNonAtomic(cdol2Value, logTemplate[(short)(i+0x01)], tmpBuf, sTradeLogLen, logTemplate[(short)(i+0x02)]);
				break;
			case LOG_VALUE_TYPE_CARD:
				sTradeLogLen = Util.arrayCopyNonAtomic(cardDataBuf, logTemplate[(short)(i+0x01)], tmpBuf, sTradeLogLen, logTemplate[(short)(i+0x02)]);
				break;
			default:
				sTradeLogLen = Util.arrayFillNonAtomic(tmpBuf, sTradeLogLen, logTemplate[(short)(i+0x02)], (byte)0x00);
				break;
			}
			
			i += 0x03;			
		}
		
		short sRecLen = Util.getShort(tradeLogFile, LOG_INFO_OFF_RECLEN);
		short fileSize = (short) tradeLogFile.length;
		short sOffset = LOG_INFO_OFF_CONTENT;
		short sDstOffset = LOG_INFO_OFF_CONTENT;
		while (sOffset < fileSize) {
			if (PBOCUtil.arrayCompare(tradeLogFile, sOffset, tradeLogFile, sDstOffset, (short)0x04) == 1) {
				sDstOffset = sOffset;				
			}
			
			sOffset += sRecLen;
		}
		
		// increase counter
		PBOCUtil.arrayHexAdd(tradeLogFile, sDstOffset, LOG_INCREASE_VAR, (short)0x00, tmpBuf, (short)0x00, (short)0x04);
		
		if (!PBOCUtil.isAllZero(tradeLogFile, sDstOffset, (short)0x04)) {
			sDstOffset += sRecLen;
			if (sDstOffset == fileSize) {
				sDstOffset = LOG_INFO_OFF_CONTENT;
			}
		}
						
		// write trade log
		Util.arrayCopyNonAtomic(tmpBuf, (short)0x00, tradeLogFile, sDstOffset, sTradeLogLen);
	}
	
	/**
	 * record charge log
	 * @param beforeValue			before value buffer
	 * @param sBeforeOff			before value buffer offset
	 * @param afterValue			after value buffer
	 * @param sAfterOff				after value buffer offset
	 * @param sTag					tag
	 * @param abyCurTradeCDOL		CDOL
	 * @param abyCurTradeCDOLValue	CDOL Value
	 * @param abyCurTradePDOL		PDOL
	 * @param tmpBuf				temp buffer
	 */
	private void updateChargeLog(byte[] beforeValue, short sBeforeOff, byte[] afterValue, short sAfterOff, short sTag, byte[] abyCurTradePDOL, byte[] tmpBuf) {
		if (chargeLogFile == null) {
			return;
		}
		
	    // 1. Put Data命令的P1值（取值为0x9F或0xDF）
	    // 2. Put Data命令的P2值（取值为0x79）
	    // 3. Put Data修改前9F79或DF79的值
	    // 4. Put Data修改后9F79或DF79的值
		short sLen = 0x04;
		sLen = Util.setShort(tmpBuf, sLen, sTag);
		sLen = Util.arrayCopyNonAtomic(beforeValue, sBeforeOff, tmpBuf, sLen, (short)0x06);
		sLen = Util.arrayCopyNonAtomic(afterValue, sAfterOff, tmpBuf, sLen, (short)0x06);
		
		// 5. 圈存日志格式（DF4F）中定义的数据元的值
		short i = 0x00;
		short logFormatLen = (short) chargelogFormat.length;
		short sPDOLLen = (short)abyCurTradePDOL.length;
		while (i < logFormatLen) {
			sTag = (short) (chargelogFormat[i++]&0x0FF);
			if ((short)(sTag&0x01F) == (short)0x1F) {
				sTag <<= 0x08;
				sTag |= (short) (chargelogFormat[i++]&0x0FF);
			}
			
			short sValueLen = (short) (chargelogFormat[i++]&0x0FF);
			
			// find tag in cdol1 TLList
			short sOff = PBOCUtil.findValuePosInTLList(sTag, cdol1, (short)0x00, (short)cdol1.length);
			if (sOff != PBOCUtil.TAG_NOT_FOUND) {
				sLen = Util.arrayCopyNonAtomic(cdol1Value, sOff, tmpBuf, sLen, sValueLen);
				
				continue;
			}
			
			// if not find in cdol1 then find in cdol2
			sOff = PBOCUtil.findValuePosInTLList(sTag, cdol2, (short)0x00, (short)cdol2.length);
			if (sOff != PBOCUtil.TAG_NOT_FOUND) {
				sLen = Util.arrayCopyNonAtomic(cdol2Value, sOff, tmpBuf, sLen, sValueLen);
				
				continue;
			}
			
			// find tag in pdol TLList
			sOff = PBOCUtil.findValuePosInTLList(sTag, abyCurTradePDOL, (short)0x00, sPDOLLen);
			if (sOff != PBOCUtil.TAG_NOT_FOUND) {
				sLen = Util.arrayCopyNonAtomic(pdolValue, sOff, tmpBuf, sLen, sValueLen);
				
				continue;
			}
			
			sOff = findTagInAnalyseTable(sTag);
			if (sOff == INVALID_VALUE) {
				sLen = Util.arrayFillNonAtomic(tmpBuf, sLen, sValueLen, (byte)0x00);
			} else {
				sLen = Util.arrayCopyNonAtomic(cardDataBuf, analyseTable[(short)(sOff+ANALYSE_TABLE_OFF_VALUE_OFF)], tmpBuf, sLen, sValueLen);
			}			
		}

		short sRecLen = Util.getShort(chargeLogFile, LOG_INFO_OFF_RECLEN);
		short fileSize = (short) chargeLogFile.length;
		short sOffset = LOG_INFO_OFF_CONTENT;
		short sDstOffset = LOG_INFO_OFF_CONTENT;
		while (sOffset < fileSize) {
			if (PBOCUtil.arrayCompare(chargeLogFile, sOffset, chargeLogFile, sDstOffset, (short)0x04) == 1) {
				sDstOffset = sOffset;
			}
			
			sOffset += sRecLen;
		}
				
		// increase counter
		PBOCUtil.arrayHexAdd(chargeLogFile, sDstOffset, LOG_INCREASE_VAR, (short)0x00, tmpBuf, (short)0x00, (short)0x04);
		
		if (!PBOCUtil.isAllZero(chargeLogFile, sDstOffset, (short)0x04)) {
			sDstOffset += sRecLen;
			if (sDstOffset == fileSize) {
				sDstOffset = LOG_INFO_OFF_CONTENT;
			}
		}
		
		// write trade log
		Util.arrayCopyNonAtomic(tmpBuf, (short)0x00, chargeLogFile, sDstOffset, sLen);
	}
	
	/**
	 * update trade data
	 * @param tradeResult			trade result
	 * @param abyCurTradeCDOLValue	CDOL
	 * @param tmpBuf				temp buffer
	 */
	private void updateTradeData(byte tradeResult, byte[] abyCurTradeCDOLValue, byte[] tmpBuf) {		
		if (tradeResult == TRADE_RESULT_ARQC) {
			Util.arrayCopy(abyCurTradeCardData, CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR, cardDataBuf, CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR, (short)(CARD_DATA_OFF_LAST_TRADE_REFUSE_DDA_FAILED+0x01-CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR));
			return;
		}
		
		boolean bIsECTrade = (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] == TRADE_TYPE_EC);
		
		JCSystem.beginTransaction();
		
		short tradeCoinCodeOff;
		short stateCodeOff;
		
		if (abyCurTradeCDOLValue == cdol1Value) {
			tradeCoinCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_COIN_CODE]&0x0FF);
			stateCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TERMINAL_STATE_CODE]&0x0FF);
		} else {
			tradeCoinCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_COIN_CODE]&0x0FF);
			stateCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TERMINAL_STATE_CODE]&0x0FF);
		}
		
		// 脱机接受
		if (tradeResult == TRADE_RESULT_TC) {
			// 发卡行针对持卡人主账户余额进行交易授权。金额从主账户中支出（电子现金余额不受影响）
			// 仅当执行第一条generate AC指令时更新卡上电子现金余额等数据
			short[] logTemplate;			
			if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_GAC_CNTR] == 0x01) {
				if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_INTERFACE] == TRADE_INTERFACE_CONTACTLESS) {					
					logTemplate = logTemplate_3;
				} else {
					logTemplate = logTemplate_1;			
				}

				/**
				 * 当交易是电子现金交易且脱机同意时将扣除电子现金余额
				 * 当卡片进行联机授权时，电子现金交易不扣除卡上余额，而是从主账户扣除
				 * 如果卡请求联机授权但终端不支持联机功能，则进行标准的借记/贷记交易处理
				 */
				if (bIsECTrade) {
					short sOff;					
					// 电子现金余额减去交易金额
					if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE]) {
						sOff = CARD_DATA_OFF_EC_SECOND_BALANCE;
					} else {
						sOff = CARD_DATA_OFF_EC_BALANCE;
					}
					
					PBOCUtil.arrayDecSub(abyCurTradeCardData, sOff, abyCurTradeCDOLValue, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY]&0x0FF), abyCurTradeCardData, sOff);					
				} else {
					/**
					 * 脱机接受累加授权金额
					 * 联机授权脱机接受则清除脱机交易金额，累计脱机交易金额不加
					 */
					// 交易货币代码=应用货币代码
					if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, abyCurTradeCDOLValue, tradeCoinCodeOff, (short)0x02) == 0x00) {
						// 累计脱机交易金额累加授权金额
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, abyCurTradeCDOLValue, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY]&0x0FF), abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY);
						// 累计脱机交易金额（双货币）累加授权金额
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, abyCurTradeCDOLValue, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY]&0x0FF), abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY);
					} else if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_SECOND_APP_COIN_CODE, abyCurTradeCDOLValue, tradeCoinCodeOff, (short)0x02) == 0x00) {
						// 交易货币代码=第2应用货币代码
						// 累计脱机交易金额（双货币）累加近似授权金额
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_TRADE_AUTH_NEAR_MONEY, abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY);
					}					
				}
			} else {
				if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_INTERFACE] == TRADE_INTERFACE_CONTACTLESS) {
					logTemplate = logTemplate_4;
				} else {
					logTemplate = logTemplate_2;
				}
			}
			
			// 保存交易日志信息
			updateTradeLog(logTemplate, tmpBuf);
		}

		// 电子现金交易的结果，不影响标准借记/贷记中各类计数器的值（ATC除外）。
		if (!bIsECTrade) {
			/**
			 * 第一条Generate AC指令脱机同意或拒绝更新计数器
			 */
			if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_GAC_CNTR] == 0x01) {
				// 交易货币代码!=应用货币代码
				if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, abyCurTradeCDOLValue, tradeCoinCodeOff, (short)0x02) != 0x00) {
					// 连续脱机交易计数器（国际-货币）加1
					abyCurTradeCardData[CARD_DATA_OFF_INTERCOINOFFLINE_ATC]++;
				}
				
				if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_ISSUE_STATE_CODE, abyCurTradeCDOLValue, stateCodeOff, (short)0x02) != 0x00) {
					// 连续脱机交易计数器（国际-国家）加1
					abyCurTradeCardData[CARD_DATA_OFF_INTERSTATEOFFLINE_ATC]++;
				}
			}
		}

		Util.arrayCopy(abyCurTradeCardData, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, cardDataBuf, CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY, (short)(CARD_DATA_OFF_ATC-CARD_DATA_OFF_AVAILABLE_OFFLINE_MONEY));
		
		JCSystem.commitTransaction();
	}
	
	/**
	 * generate response
	 * @param apduBuf				apdu buffer
	 * @param bCDA					true is generate CDA, false is not generate CDA
	 * @param abyCurTradeCDOLValue	CDOL Value
	 * @return
	 */
	private short generateRsp(byte[] apduBuf, boolean bCDA, byte[] abyCurTradeCDOLValue) {
		short sLen = 0x00;
		short sOff = 0x00;
		
		// 按格式2组织响应数据
		if (bCDA) {
			// AIP标明卡片不支持CDA
			if (!PBOCUtil.isBitSet(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, AIP_SUPPORT_OFF_CDA)) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			
			apduBuf[sOff++] = 0x77;
			// skip length byte			
			sOff++;
			// 1. 密文信息数据, TLV
			sOff = PBOCUtil.appendTLV(TAG_CID, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CID, (short)0x01, apduBuf, sOff);
			// 2. ATC, TLV
			sOff = PBOCUtil.appendTLV(TAG_ATC, cardDataBuf, CARD_DATA_OFF_ATC, (short)0x02, apduBuf, sOff);
			
			// cal AC
			generateAppCipher(abyCurTradeCDOLValue);
			if (abyCurTradeCDOLValue == cdol1Value) {
				// 存储第一条Generate AC指令的应用密文
				Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AUTH_AC, (short)0x08);
			}
			
			// 3. 签名的动态应用数据
			sLen = getRSAKeyLen();
			short sTmp = sOff;
			sOff = PBOCUtil.appendTLV(TAG_SIGN_DYNAMIC_APP_DATA, apduBuf, sOff, sLen, apduBuf, sOff);
			sOff -= sLen;
			
			// 计算交易哈希值: PDOL Value List + CDOL1 Value List (+ CDOL2 Value List)
			msgDigest.update(pdolValue, (short)0x00, curTradeConditions[CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL]?(short)(paramBuf[PBOC_PARAM_OFF_QPBOCPDOLVALUE_LEN]&0x0FF):(short)(paramBuf[PBOC_PARAM_OFF_PBOCPDOLVALUE_LEN]&0x0FF));
			msgDigest.update(cdol1Value, (short)0x00, (short)cdol1Value.length);
			
			short randomOff;
			if (abyCurTradeCDOLValue == cdol2Value) {
				msgDigest.update(cdol2Value, (short)0x00, (short)cdol2Value.length);
				randomOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TERMINAL_TRADE_RANDOM]&0x0FF);
			} else {
				randomOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TERMINAL_TRADE_RANDOM]&0x0FF);
			}
			// GAC response data TLV List, sTmp is Length
			msgDigest.update(apduBuf, (short)0x02, (short)(sTmp-0x02));
			// sTmp is 9F4B value offset
			sTmp = sOff;
			sOff += sLen;
			
			// 4. 发卡行应用数据, 可选
			short issueAppDataLen = (short)pbocIssueAppData.length;			
			sOff = PBOCUtil.appendTLV(TAG_ISSUE_APP_DATA, pbocIssueAppData, (short)0x00, issueAppDataLen, apduBuf, sOff);
			// 生成发卡行自定义数据
			generateIssueAppData(apduBuf, (short)(sOff-issueAppDataLen), issueAppDataLen);
			
			msgDigest.doFinal(apduBuf, (short)(sTmp+sLen), (short)(sOff-sTmp-sLen), apduBuf, (short)(sTmp+CDA_OFF_IC_TRADE_HASH));
			
			apduBuf[(short)(sTmp+CDA_OFF_HEADER)] = 0x6A;
			apduBuf[(short)(sTmp+CDA_OFF_SIGN_FORMAT)] = 0x05;
			apduBuf[(short)(sTmp+CDA_OFF_HASH_IDENTIFIER)] = 0x01;
			apduBuf[(short)(sTmp+CDA_OFF_IC_DATA_LEN)] = 0x20;
			apduBuf[(short)(sTmp+CDA_OFF_IC_DATA_DIGIT_LEN)] = 0x02;
			// replace ATC
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, (short)(sTmp+CDA_OFF_IC_DATA_DIGIT), (short)0x02);
			// replace CID
			apduBuf[(short)(sTmp+CDA_OFF_IC_DATA_CID)] = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID];
			// replace AC
			Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC, apduBuf, (short)(sTmp+CDA_OFF_IC_DATA_AC), (short)0x08);
			Util.arrayFillNonAtomic(apduBuf, (short)(sTmp+CDA_OFF_PADDING_BB), (short)(sLen-57), (byte)0xBB);
									
			// 计算签名哈希值
			msgDigest.update(apduBuf, (short)(sTmp+CDA_OFF_SIGN_FORMAT), (short)(sLen-22));			
			msgDigest.doFinal(abyCurTradeCDOLValue, randomOff, (short)0x04, apduBuf, (short)(sTmp+sLen-21));
			apduBuf[(short)(sTmp+sLen-0x01)] = (byte)0xBC;
			cipherRSA.doFinal(apduBuf, sTmp, sLen, apduBuf, sTmp);			
									
			sLen = (short)(sOff - 2);
			if (sLen > 0x7F) {
				Util.arrayCopyNonAtomic(apduBuf, (short)0x02, apduBuf, (short)0x03, sLen);
				apduBuf[0x01] = (byte)0x81;
				apduBuf[0x02] = (byte)sLen;
				sOff++;
			} else {
				apduBuf[0x01] = (byte)sLen;
			}
		} else {
			// 按格式1组织响应数据
			apduBuf[sOff++] = (byte)0x80;
			// skip length byte
			sOff++;
			// 1. 密文信息数据, M, 1 byte
			apduBuf[sOff++] = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID];
			// 2. ATC, M, 2 byte
			sOff = Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, sOff, (short)0x02);
			// cal AC
			generateAppCipher(abyCurTradeCDOLValue);
			// 3. 应用密文, M, 8 byte
			sOff = Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC, apduBuf, sOff, (short)0x08);
			if (abyCurTradeCDOLValue == cdol1Value) {
				// 存储第一条Generate AC指令的应用密文
				Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AC, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AUTH_AC, (short)0x08);
			}
			// 4. 发卡行应用数数据
			short issueAppDataLen = (short)pbocIssueAppData.length;
			sOff = Util.arrayCopyNonAtomic(pbocIssueAppData, (short)0x00, apduBuf, sOff, issueAppDataLen);
			// 生成发卡行自定义数据
			generateIssueAppData(apduBuf, (short)(sOff-issueAppDataLen), issueAppDataLen);
			
			apduBuf[0x01] = (byte)(sOff-0x02);
		}
		
		return sOff;
	}
	
	/**
	 * generate GAC 1 response data
	 * @param apduBuf			apdu buffer
	 * @param acType			ac type
	 * @param cardTradeResult	card trade result
	 * @param bCDA				true is generate CDA, false is not generate CDA
	 * @return	response data length
	 */
	private short getGenerateACRsp_1(byte[] apduBuf, byte acType, byte cardTradeResult, boolean bCDA) {
		byte tradeResult;
		
		// 终端请求AAC或卡片请求脱机拒绝指示位=1
		if ((acType == GENERATE_AC_TYPE_AAC)
			|| (cardTradeResult == TRADE_RESULT_AAC)) {
			// 设置CVR中"第1个生成应用密文命令返回AAC""第2个生成应用密文命令没请求"
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_1ST_GEN_AC_MASK))|CVR_1ST_GEN_AC_RETURN_AAC);
			
			// 设置CID中密文类型为AAC
			setCIDACType(CID_AC_TYPE_AAC);
			
			// ADA标明"如果脱机拒绝，生成通知"
			if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_TRADE_REFUSE)) {
				// 设置CID中"需要通知"
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID] |= CID_REQUEST_MSG;
			}
			
			// 本次交易PIN尝试限制数超过？
			if (PBOCUtil.isBitSet(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_BLOCKED)
				&& (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR] > 0x00)) {
				// ADA标明“本次交易PIN尝试限制数超过，交易拒绝，生成通知”？
				if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_PIN_VERIFY_EXCEED_AND_TRADE_AAC)) {
					// 设置CID中“需要通知”位=1，原因码为"PIN尝试限制数超"
					abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID] |= CID_REQUEST_MSG;
					setCIDReasonCode(CID_REASON_CODE_PIN_EXCEED);
				}				
			}
			
			short tvrOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TVR]&0x0FF);
			// TVR中SDA失败
			if (PBOCUtil.isBitSet(cdol1Value, tvrOff, TVR_BIT_OFFSET_SDA_FAILED)) {
				// 设置SDA失败指示位
				abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_REFUSE_SDA_FAILED] = 0x01;
			}
			
			// TVR中CDA/DDA失败
			if (PBOCUtil.isBitSet(cdol1Value, tvrOff, TVR_BIT_OFFSET_DDA_FAILED)
				|| PBOCUtil.isBitSet(cdol1Value, tvrOff, TVR_BIT_OFFSET_CDA_FAILED)) {
				// 设置DDA失败指示位
				abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_REFUSE_DDA_FAILED] = 0x01;
			}
			
			bCDA = false;
			tradeResult = TRADE_RESULT_AAC;
		} else if ((acType == GENERATE_AC_TYPE_ARQC) || (cardTradeResult == TRADE_RESULT_ARQC)) {
			// 终端请求ARQC或卡片请求联机指示位=1
			// 设置CVR中“第1个生成应用密文命令返回ARQC”"第2个生成应用密文命令没请求"
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_1ST_GEN_AC_MASK))|CVR_1ST_GEN_AC_RETURN_ARQC);
			// 设置CID中密文类型为ARQC
			setCIDACType(CID_AC_TYPE_ARQC);
			// 设置联机授权指示位为1
			abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ONLINE_AUTH] = 0x01;
			
			tradeResult = TRADE_RESULT_ARQC;
		} else {
			// 请求TC
			// 设置CVR中"第1个生成应用密文命令返回TC", "第2个生成应用密文命令没请求"
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_1ST_GEN_AC_MASK))|CVR_1ST_GEN_AC_RETURN_TC);
			// 设置CID中密文类型为TC
			setCIDACType(CID_AC_TYPE_TC);
			// 联机授权指示位复位
			// 若是电子现金交易，则不影响联机授权指示位
			if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] != TRADE_TYPE_EC) {
				abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ONLINE_AUTH] = 0x00;
			}
			
			tradeResult = TRADE_RESULT_TC;
		}
		
		// "第2个生成应用密文命令没请求"
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_2ND_GEN_AC_MASK))|CVR_2ND_GEN_AC_NO_REQ);
		
		if (bCDA) {
			// 设置CVR中DDA执行位指示器
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_DDA_EXEC);
		}
		
		// 更新交易数据
		updateTradeData(tradeResult, cdol1Value, apduBuf);
		
		/**
		 * 1. 第一条Generate AC指令当 交易结束并且应用未锁定时清除交易状态信息
		 * 2. 应用锁定后Generate AC指令均返回AAC，但后续要求可以执行External Auth，Application UnBlock等指令，因此不可清除交易状态信息
		 * 	  避免交易结束后发送发卡行脚本处理指令
		 * 3. PIN锁以后，也不可清除交易状态信息，用于执行发卡行脚本命令解锁PIN???
		 */
		if ((tradeResult != TRADE_RESULT_ARQC)
			&& (appState != APP_STATE_LOCKED)
			&& (paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] != 0x00)) {
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] = TRADE_STATE_INVALID;
		}
				
		return generateRsp(apduBuf, bCDA, cdol1Value);
	}	
	
	/**
	 * online trade reset session data
	 * @param bType 
	 */
	private void onLineResetSessionData(boolean bType) {
		/**
		 * 复位成0
		 * -联机授权指示器
		 * -SDA 失败指示器
		 * -DDA 失败指示器
		 * -发卡行脚本指令计数器
		 * -发卡行脚本失败指示位
		 */
		Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR, (short)(CARD_DATA_OFF_CARD_TRADE_ATTRIBUTE-CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR), (byte)0x00);
		if (bType) {
			/**
			 * 清除
			 * -累计脱机交易金额
			 * -累计脱机交易金额（双货币）
			 * -连续脱机交易计数器（国际-货币）
			 * -连续脱机交易计数器（国际-国家）
			 */
			Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, (short)0x06, (byte)0x00);
			Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, (short)0x06, (byte)0x00);
			abyCurTradeCardData[CARD_DATA_OFF_INTERCOINOFFLINE_ATC] = 0x00;
			abyCurTradeCardData[CARD_DATA_OFF_INTERSTATEOFFLINE_ATC] = 0x00;
			// 上次联机ATC寄存器=ATC
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC, (short)0x02);
		}
	}
	
	/**
	 * generate GAC 2 response data
	 * @param apduBuf			apdu buffer
	 * @param bCDA				true is generate CDA, false is not generate CDA
	 * @param bAuth				online is auth
	 * @param acType			ac type
	 * @param cardTradeResult	card trade result
	 * @return
	 */
	private short getGenerateACRsp_2(byte[] apduBuf, boolean bCDA, boolean bAuth, byte acType, byte cardTradeResult) {			
		// true 响应码不是拒绝; false 响应码表示拒绝
		boolean bAccept = false;
		// true 卡片接受; false 卡片拒绝
		boolean bFlag = true;
		boolean bIsSupportExtAuth = PBOCUtil.isBitSet(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, AIP_SUPPORT_OFF_ISSUE_AUTH);
		byte extAuthCmdCntr = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_AUTH_CNTR];
		byte tradeResult;
		
		short authCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_AUTH_CODE]&0x0FF);
		if (bAuth) {
			/**
			 * 检查第 2 个生成应用密文（GENERATE AC）命令中的 P1 参数： 
			 * 如果 P1 表明请求 TC（接受交易）而且授权响应码表明发卡行接受或推荐，执行交易接受
			 * 处理。见 16.6.2 中的描述；  
			 * 如果 P1 表明请求 AAC（拒绝交易）或者授权响应码表明发卡行拒绝，执行交易拒绝处理。
			 * 见 16.6.1 中的描述。
			 */
			if ((Util.arrayCompare(AUTH_CODE_00, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)
				|| (Util.arrayCompare(AUTH_CODE_10, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)
				|| (Util.arrayCompare(AUTH_CODE_11, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)
				|| (Util.arrayCompare(AUTH_CODE_01, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)
				|| (Util.arrayCompare(AUTH_CODE_02, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)
				|| (Util.arrayCompare(AUTH_CODE_Y1, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)) {
				bAccept = true;
			}
			
			// 1. 卡片支持外部认证
			// 2. 执行过外部认证指令
			// 3. 外部认证执行成功
			if (bAccept
				&& bIsSupportExtAuth
				&& (extAuthCmdCntr>0x00)
				&& (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] == 0x00)) {
				/**
				 * 如果发卡行认证执行，检查在外部认证命令中送来的授权响应码
				 * 授权响应码为 00，10 或11 表明发卡行接受交易；
				 * 授权响应码为 01 或02 表明发卡行请求参考
				 * 其它值表明发卡行拒绝，卡片按照终端请求交易拒绝进行处理
				 */
				if ((Util.arrayCompare(AUTH_CODE_00, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE, (short)0x02) == 0x00)
					|| (Util.arrayCompare(AUTH_CODE_10, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE, (short)0x02) == 0x00)
					|| (Util.arrayCompare(AUTH_CODE_11, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE, (short)0x02) == 0x00)
					|| (Util.arrayCompare(AUTH_CODE_01, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE, (short)0x02) == 0x00)
					|| (Util.arrayCompare(AUTH_CODE_02, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE, (short)0x02) == 0x00)
					|| (Util.arrayCompare(AUTH_CODE_Y1, (short)0x00, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE, (short)0x02) == 0x00)) {					
					bAccept = true;
				} else {
					bAccept = false;
				}				
			}
			
			// 联机成功			
			// 请求密文类型是TC 而且响应码不是拒绝
			if ((acType == GENERATE_AC_TYPE_TC) && bAccept) {
				// 联机接受
				// 支持发卡行认证？
				if (bIsSupportExtAuth) {
					// 执行发卡行认证？
					if (extAuthCmdCntr == 0x00) {
						// 发卡行认证可选？
						if ((cardDataBuf[CARD_DATA_OFF_ISSUE_AUTH_INDICATE]&(byte)0x80) == (byte)0x80) {
							// 设置发卡行认证失败指示位=1
							abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] = 0x01;
							// ADA 中“如果发卡行认证强制但没有收到ARPC ，交易拒绝”位 =1
							if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_ISSUE_AUTH_M_NO_ARPC)) {
								bFlag = false;
							}
						}
					} else {
						// 发卡行认证失败指示位=1 && ADA 中“发卡行认证失败，拒绝交易”位 =1
						if ((abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] == 0x01)
							&& PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_ISSUE_AUTH_EXEC_FAILED)) {
							bFlag = false;
						}
					}
				}
				
				if (bFlag) {
					// 卡片接受
					// 设置CVR中密文类型为TC
					abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_2ND_GEN_AC_MASK))|CVR_2ND_GEN_AC_RETURN_TC);
					// 设置CID中密文类型
					setCIDACType(CID_AC_TYPE_TC);
					// 支持发卡行认证？
					if (bIsSupportExtAuth) {
						// 执行发卡行认证？
						if (extAuthCmdCntr == 0x00) {
							// 设置CVR“联机授权后发卡行认证没执行”位=1
							PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_ONLINE_AUTHED_ISSUE_AUTH_UNEXEC);
							
							// 发卡行认证强制？
							if (!((cardDataBuf[CARD_DATA_OFF_ISSUE_AUTH_INDICATE]&(byte)0x80) == (byte)0x80)) {
								onLineResetSessionData(true);
							}
						} else if (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] == 0x00){
							// 发卡行认证成功
							onLineResetSessionData(true);
						}
					} else {
						onLineResetSessionData(true);
					}
					
					tradeResult = TRADE_RESULT_TC;
				} else {
					// 卡片拒绝
					// 设置CVR中密文类型为AAC
					abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_2ND_GEN_AC_MASK))|CVR_2ND_GEN_AC_RETURN_AAC);
					// 设置CID中密文类型
					setCIDACType(CID_AC_TYPE_AAC);
					// ADA中“如果发卡行认证失败或强制不执行，生成通知”位=1
					if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_TRADE_REFUST_ISSUE_AUTH_FAILED)) {
						// 设置CID“需要通知”位=1
						abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID] |= CID_REQUEST_MSG;
					}
					
					bCDA = false;
					tradeResult = TRADE_RESULT_AAC;
				}
			} else {
				// 设置 CVR 中第 2个生成应用密文返回AAC
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_2ND_GEN_AC_MASK))|CVR_2ND_GEN_AC_RETURN_AAC);
				// 支持发卡行认证？
				if (bIsSupportExtAuth) {
					// 执行发卡行认证？
					if (extAuthCmdCntr == 0x00) {
						// 设置 CVR 中“联机授权后发卡行认证没有执行”位 =1
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_ONLINE_AUTHED_ISSUE_AUTH_UNEXEC);
						// 发卡行认证可选？
						if ((cardDataBuf[CARD_DATA_OFF_ISSUE_AUTH_INDICATE]&(byte)0x80) == (byte)0x80) {
							// 设置发卡行认证失败指示位
							abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] = 0x01;
						} else {
							onLineResetSessionData(false);
						}
					} else if (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] == 0x00) {
						// 发卡行认证成功？
						onLineResetSessionData(false);
					}
				} else {
					onLineResetSessionData(false);
				}
				
				// 设置CID中密文类型AAC
				setCIDACType(CID_AC_TYPE_AAC);
				bCDA = false;
				tradeResult = TRADE_RESULT_AAC;
			}
		} else {
			short tradeCoinCode = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_COIN_CODE]&0x0FF);
			
			// 不能联机
			// 发卡行国家代不等于终端国家代码
			if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_ISSUE_STATE_CODE, cdol2Value, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TERMINAL_STATE_CODE]&0x0FF), (short)0x02) != 0x00) {
				// 连续脱机交易计数器（国际-国家）加1
				abyCurTradeCardData[CARD_DATA_OFF_INTERSTATEOFFLINE_ATC]++;
			}
			
			// 交易货币代码!=应用货币代码
			if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, cdol2Value, tradeCoinCode, (short)0x02) != 0x00) {
				// 连续脱机交易计数器（国际-货币）加1
				abyCurTradeCardData[CARD_DATA_OFF_INTERCOINOFFLINE_ATC]++;
			}
			
			// 终端请求AAC？|| 卡片请求拒绝指示位=1？
			if ((acType == GENERATE_AC_TYPE_AAC)
				|| (cardTradeResult == TRADE_RESULT_AAC)) {
				// 设置 CVR 中第 2个生成应用密文返回AAC
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_2ND_GEN_AC_MASK))|CVR_2ND_GEN_AC_RETURN_AAC);
				// TVR中表明SDA失败
				short tvrOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TVR]&0x0FF);
				if (PBOCUtil.isBitSet(cdol2Value, tvrOff, TVR_BIT_OFFSET_SDA_FAILED)) {
					// 设置SDA失败指示位
					abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_REFUSE_SDA_FAILED] = 0x01;
				} else if (PBOCUtil.isBitSet(cdol2Value, tvrOff, TVR_BIT_OFFSET_DDA_FAILED)
							|| PBOCUtil.isBitSet(cdol2Value, tvrOff, TVR_BIT_OFFSET_CDA_FAILED)) {
					// 设置DDA失败指示位
					abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_REFUSE_DDA_FAILED] = 0x01;
				}
				
				// ADA中“如果交易拒绝，需要通知”位=1？
				if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_TRADE_REFUSE)) {
					// 设置CID中“需要通知”位
					abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID] |= CID_REQUEST_MSG;
				}
				
				// 设置CID中密文类型AAC
				setCIDACType(CID_AC_TYPE_AAC);
				bCDA = false;
				tradeResult = TRADE_RESULT_AAC;
			} else {
				// 脱机批准
				// 设置CVR"第2个生成应用密文返回TC"
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR] = (byte) ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&(~CVR_2ND_GEN_AC_MASK))|CVR_2ND_GEN_AC_RETURN_TC);
				// 设置CID中密文类型
				setCIDACType(CID_AC_TYPE_TC);
				
				// 交易货币代码=应用货币代码
				if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, cdol2Value, tradeCoinCode, (short)0x02) == 0x00) {
					// 累计脱机交易金额累加授权金额
					PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, cdol2Value, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY]&0x0FF), abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY);					
					// 累计脱机交易金额（双货币）累加授权金额
					PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, cdol2Value, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY]&0x0FF), abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY);
				} else if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_SECOND_APP_COIN_CODE, cdol2Value, tradeCoinCode, (short)0x02) == 0x00) {
					// 交易货币代码=第2应用货币代码
					// 累计脱机交易金额（双货币）累加近似授权金额
					PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_TRADE_AUTH_NEAR_MONEY, abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY);
				}
				
				tradeResult = TRADE_RESULT_TC;
			}
		}
		
		// 设置CVR中DDA执行位指示器
		if (bCDA) {
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_DDA_EXEC);
		}
		
		// 更新交易数据
		updateTradeData(tradeResult, cdol2Value, apduBuf);
		
		return generateRsp(apduBuf, bCDA, cdol2Value);
	}
	
	/**
	 * generate AC command process
	 * @param apdu
	 */
	private void onGenerateAC(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
				
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x80) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check p1 && p2
		byte p1 = apduBuf[ISO7816.OFFSET_P1];
		byte acType = (byte)(p1&GENERATE_AC_TYPE_MASK);
		if (acType == GENERATE_AC_TYPE_MASK) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		if (apduBuf[ISO7816.OFFSET_P2] != 0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}

		byte cmdCntr = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_GAC_CNTR];		
		byte[] abyCurTradeCDOLValue;
		byte[] abyCurTradePDOL;		
		
		if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL]) {
			abyCurTradePDOL = qpbocpdol;			
		} else {
			abyCurTradePDOL = pbocpdol;			
		}
		
		short tradeCoinCodeOff;
		if (cmdCntr == 0x00) {			
			abyCurTradeCDOLValue = cdol1Value;
			tradeCoinCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_COIN_CODE]&0x0FF);
			curTradeConditions[CURRENT_TRADE_CONDITION_OFF_CDOL1] = true;
		} else {			
			abyCurTradeCDOLValue = cdol2Value;
			tradeCoinCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_COIN_CODE]&0x0FF);
			curTradeConditions[CURRENT_TRADE_CONDITION_OFF_CDOL1] = false;
		}
		
		// check p3
		if ((short)(apduBuf[ISO7816.OFFSET_LC]&0x0FF) != (short)abyCurTradeCDOLValue.length) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		// receive data
		apdu.setIncomingAndReceive();
		
		// trade flow check
		byte tradeState = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE];
		short tradeAuthMoneyOff = 0x00;
		if ((tradeState == TRADE_STATE_APP_INIT)
			|| (tradeState == TRADE_STATE_OFF_LINE_AUTH)) {
			// Generate AC 1
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] = TRADE_STATE_CARD_ACTION_ANALYSE;
			tradeAuthMoneyOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL1_TRADE_AUTH_MONEY]&0x0FF);
		} else if (tradeState == TRADE_STATE_CARD_ACTION_ANALYSE) {
			// Generate AC 2
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] = TRADE_STATE_ON_LINE;
			tradeAuthMoneyOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY]&0x0FF);
		} else {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		// increase Generate AC execute counter
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_GAC_CNTR]++;
		
		// save CDOL Value
		Util.arrayCopyNonAtomic(apduBuf, ISO7816.OFFSET_CDATA, abyCurTradeCDOLValue, (short)0x00, (short)abyCurTradeCDOLValue.length);		
				
		// 根据货币转换因子转换近似授权金额
		if (!PBOCUtil.isAllZero(cardDataBuf, CARD_DATA_OFF_COIN_CONVERT_GENE, (short)0x04)) {
			Util.arrayFillNonAtomic(apduBuf, (short)0x00, (short)33, (byte)0x00);
									
			Util.arrayCopyNonAtomic(abyCurTradeCDOLValue, tradeAuthMoneyOff, apduBuf, (short)0x00, (short)0x06);
			Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_COIN_CONVERT_GENE, apduBuf, (short)0x08, (short)0x04);
			// 货币转换因子 4 byte
			// 字节1 位8-5：小数点位置。从右边开始移动的位数 位4-1：转换因子的第1个数字 
			// 字节2-4：剩下的6个数字
			byte gene = (byte)(apduBuf[0x08]>>0x04);
			apduBuf[0x08] &= 0x0F;
			
			PBOCUtil.arrayDecMul(apduBuf, (short)0x00, apduBuf, (short)0x06, apduBuf, (short)12, gene);
			
			Util.arrayCopyNonAtomic(apduBuf, (short)12, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_TRADE_AUTH_NEAR_MONEY, (short)0x06);
		}
		
		
		// 一个锁定的应用，卡片对生成应用密文命令总是返回AAC
		if (appState == APP_STATE_LOCKED) {
			acType = GENERATE_AC_TYPE_AAC;
		}	
		
		short sLen;
		boolean bCDA = ((byte)(p1&GENERATE_AC_CDA) == GENERATE_AC_CDA);
		byte cardTradeResult;
		
		// clear CID information
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CID] = 0x00;
		
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_TYPE] != TRADE_TYPE_EC) {
			if (Util.arrayCompare(abyCurTradeCDOLValue, tradeCoinCodeOff, cardDataBuf, CARD_DATA_OFF_APPCOINCODE, (short)0x02) == 0x00) {
				curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE] = false;
			} else if (Util.arrayCompare(abyCurTradeCDOLValue, tradeCoinCodeOff, cardDataBuf, CARD_DATA_OFF_EC_SECOND_APP_COIN_CODE, (short)0x02) == 0x00) {
				curTradeConditions[CURRENT_TRADE_CONDITION_OFF_SECOND_COIN_TRADE] = true;
			}
		}
				
		if (cmdCntr == 0x00) {
			// card risk manager
			cardTradeResult = cardRiskManager_1(acType, abyCurTradePDOL, apduBuf);
			// gete response data
			sLen = getGenerateACRsp_1(apduBuf, acType, cardTradeResult, bCDA);
		} else {
			// 第二条Generate AC指令请求ARQC返回0x6985
			if (acType == GENERATE_AC_TYPE_ARQC) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			
			cardTradeResult = TRADE_RESULT_TC;
			short authMoneyOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_AUTH_MONEY]&0x0FF);
			short authCodeOff = (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_AUTH_CODE]&0x0FF);
			if ((Util.arrayCompare(AUTH_CODE_Y3, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)
				|| (Util.arrayCompare(AUTH_CODE_Z3, (short)0x00, cdol2Value, authCodeOff, (short)0x02) == 0x00)) {
				// 联机授权没完成, 执行卡片风险管理
				/**
				 * 1. 连续脱机交易上限频度检查
				 * 此检查可选。检查连续脱机交易次数是否超过了最大限制。 
				 * 如果上次联机ATC寄存器和JR/T  0025专有数据：连续脱机交易上限（标签“9F59”）存在，卡片执行此检查。
				 * 如果ATC和上次联机ATC寄存器的差值大于连续脱机交易上限，卡片： 
				 * ——设置 CVR 中“频度检查超过”位为“1”； 
				 * ——设置卡片请求脱机拒绝指示位为“1”。在卡片风险管理后，卡片返回交易拒绝。
				 */
				if (cardDataBuf[CARD_DATA_OFF_OFFLINE_CARD_UPLIMIT] != (byte)0xFF) {
					short sATC = Util.getShort(cardDataBuf, CARD_DATA_OFF_ATC);
					short sPreOnlineATC = Util.getShort(abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC);
					
					if ((short)(sATC-sPreOnlineATC) > (short)(cardDataBuf[CARD_DATA_OFF_OFFLINE_CARD_UPLIMIT]&0x0FF)) {
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);						
						cardTradeResult = TRADE_RESULT_AAC;
					}
				}
				
				/**
				 * 2. 新卡检查
				 * 此检查可选。检查以前是否有过联机接受的交易。 
				 * 如果卡片中上次联机ATC寄存器存在，卡片执行此检查。如果ADA不存在，卡片认为缺省为零。 
				 * 如果上次联机ATC寄存器值为零，卡片： 
				 * ——设置 CVR 中“新卡”位为“1”； 
				 * ——如果 ADA 中“如果是新卡而且交易无法联机，交易拒绝”位为“1”，设置卡片请求脱机拒绝指示位为“1”。在卡片风险管理后，卡片返回交易拒绝。
				 */
				if (PBOCUtil.isAllZero(abyCurTradeCardData, CARD_DATA_OFF_PREONLINE_ATC, (short)0x02)) {
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_NEW_CARD);
					if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_NEW_CARD_CANNOT_ARQC)) {						
						cardTradeResult = TRADE_RESULT_AAC;
					}
				}
				
				/**
				 * 3. PIN尝试限制数超过检查
				 * 此项检查可选，检查PIN尝试限制数是否在之前的交易中就已经超过。 
				 * 如果卡片中没有ADA数据，卡片认为ADA值缺省为零。 
				 * 如果卡片支持脱机PIN验证，而且在本次交易中，卡片没有收到过验证命令，卡片： 
				 * ——如果 PIN 尝试计数器已经为零，而且如果 ADA 中“如果上次交易 PIN 尝试限制数超过而且交易无法联机，交易拒绝”位为“1”： 
				 * 设置卡片请求脱机拒绝指示位为“1”；
				 * 设置 CVR 中“PIN 尝试限制数超过”位为“1”。
				 */
				if ((paramBuf[PBOC_PARAM_OFF_PIN_MAX_CNTR] != 0x00)			
					&& (paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] == 0x00)
					&& (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR] == 0x00)
					&& PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_LAST_TRADE_PIN_VERIFY_EXCEED_CANNOT_ARQC_AAC)) {					
					cardTradeResult = TRADE_RESULT_AAC;
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_BLOCKED);
				}
				
				/**
				 * 4. 累计脱机交易金额（上限）频度检查
				 * 此检查可选。检查使用指定货币的连续脱机交易累计金额是否超过了最大限制数。 
				 * 如果累计脱机交易金额和累计脱机交易金额上限数据存在，卡片执行此检查。 
				 * 如果累计脱机交易金额加本次授权金额大于累计脱机交易金额上限。 
				 * 卡片： 
				 * ——设置 CVR 中频度检查超过位为“1”； 
				 * ——设置卡片请求脱机拒绝指示位为“1”。
				 */
				if (!PBOCUtil.isAllZero(cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, (short)0x06)) {
					PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_TOTAL_OFFILINE_MONEY, cdol2Value, authMoneyOff, apduBuf, (short)0x00);
					if (PBOCUtil.arrayCompare(apduBuf, (short)0x00, cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, (short)0x06) == 1) {
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);						
						cardTradeResult = TRADE_RESULT_AAC;
					}
					
					/**
					 * 5. 累计脱机交易金额上限（双货币）频度检查
					 * 此检查可选。检查使用指定货币和第2应用货币的连续脱机交易累计金额是否超过了最大限制数。 
					 * 如果累计脱机交易金额（双货币）和累计脱机交易金额上限数据存在，卡片执行此检查。 
					 * 如果累计脱机交易金额加本次授权金额（如果使用第2应用货币要先使用货币转换因子转换）大于累计脱机交易金额上限。 
					 * 卡片： 
					 * ——设置 CVR 中频度检查超过位为“1”； 
					 * ——设置卡片请求脱机拒绝指示位为“1”。
					 */
					if (Util.arrayCompare(cardDataBuf, CARD_DATA_OFF_APPCOINCODE, cdol2Value, (short)(terDataInCDOLVOff[CDOLV_OFF_CDOL2_TRADE_COIN_CODE]&0x0FF), (short)0x02) == 0x00) {
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, cdol2Value, authMoneyOff, apduBuf, (short)0x00);
					} else {
						PBOCUtil.arrayDecAdd(abyCurTradeCardData, CARD_DATA_OFF_DCOINTOTAL_OFFILINE_MONEY, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_TRADE_AUTH_NEAR_MONEY, apduBuf, (short)0x00);
					}
					
					if (PBOCUtil.arrayCompare(apduBuf, (short)0x00, cardDataBuf, CARD_DATA_OFF_TOTAL_CARD_MONEY_UPLIMIT, (short)0x06) == 0x01) {
						PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_EXCEED_FREQ_CHECK);						
						cardTradeResult = TRADE_RESULT_AAC;
					}
				}
				
				PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_CANNOT_ONLINE);
				
				sLen = getGenerateACRsp_2(apduBuf, bCDA, false, acType, cardTradeResult);
			} else {
				// 授权响应码不是Y3或Z3表明是联机授权交易
				sLen = getGenerateACRsp_2(apduBuf, bCDA, true, acType, cardTradeResult);
			}
		}
		
		apdu.setOutgoingAndSend((short)0x00, sLen);
	}
	
	/**
	 * verify PIN command process
	 * @param apdu
	 */
	private void onVerifyPIN(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check p1 && p2
		if ((apduBuf[ISO7816.OFFSET_P1] != 0x00)
			|| (apduBuf[ISO7816.OFFSET_P2] != (byte)0x80)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		if (apduBuf[ISO7816.OFFSET_LC] != 0x08) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		apdu.setIncomingAndReceive();
		
		// 设置CVR中“脱机PIN验证执行”位
		PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_OFFLINE_PIN_VERIFY);
				
		short retryCntr = (short)(paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR]&0x0FF);
		
		if (retryCntr == 0x00) {
			// 设置CVR中“脱机PIN验证失败”位
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_OFFLINE_PIN_FAILED);
			// 设置CVR中“PIN尝试限制超过”位
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_BLOCKED);
			
			if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR] == 0x00) {
				// 如果 PIN 尝试限制数是在上次交易中超过的，返回 SW1 SW2=6984
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR]++;
				ISOException.throwIt(ISO7816.SW_DATA_INVALID);
			} else {
				// 如果 PIN 尝试限制数是在本次交易中超过的，返回 SW1 SW2=6983
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR]++;
				ISOException.throwIt(ISO7816.SW_FILE_INVALID);
			}
		} 		
		
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_VERIFY_PIN_CNTR]++;
		
		if (Util.arrayCompare(apduBuf, (short)0x06, paramBuf, PBOC_PARAM_OFF_PIN_VALUE, (short)0x06) != 0x00) {
			retryCntr--;
			// 设置CVR中“脱机PIN验证失败”位
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_OFFLINE_PIN_FAILED);
			if (retryCntr == 0x00) {
				// 设置CVR中“PIN尝试限制数超过”位
				PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_BLOCKED);
				// ADA中“如果PIN尝试限制数超过，锁应用”位为1？
				if (PBOCUtil.isBitSet(cardDataBuf, CARD_DATA_OFF_ADA, ADA_OFF_PIN_VERIFY_EXCEED_LOCK_APP)) {
					// 设置CVR中“因为PIN尝试限制数超过，锁应用”位
					PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_PIN_LOCK_LOCK_APP);
					// 锁应用
					appState = APP_STATE_LOCKED;
				}
			}
			
			// 更新PIN剩余校验次数
			paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] = (byte)retryCntr;
			ISOException.throwIt((short)(SW_VERIFY_PIN_FAILED|retryCntr));
		} 

		// PIN尝试计数器复位成最大值
		paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] = paramBuf[PBOC_PARAM_OFF_PIN_MAX_CNTR];		
		// 清除CVR中“脱机PIN验证失败”位
		PBOCUtil.clearBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_OFFLINE_PIN_FAILED);
	}
	
	/**
	 * increase issue script command execute counter
	 */
	private void incrIssueScriptCmdExcCntr() {
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_GAC_CNTR] != 0x02) {
			return;
		}
		
		cardDataBuf[CARD_DATA_OFF_LAST_TRADE_EXCUTE_CMD_CNTR]++;
	}
	
	/**
	 * unwap issue script command
	 * @param buf command buffer
	 */
	private void unWrap(byte[] buf) {
		if (macFailedCntr == MAX_FAILED_COUNTER) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		
		Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
		Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);
		Util.arrayCopyNonAtomic(sessionKey, (short)0x06, sessionKey, (short)14, (short)0x02);
		sessionKey[14] ^= (byte)0xFF;
		sessionKey[15] ^= (byte)0xFF;
		
		// generate MAC Session Key
		tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_MAC_KEY);
		cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
		tripleDesKey.setKey(sessionKey, (short) 0x00);
				
		// clear channel info
		byte cls = buf[0x00];
		buf[0x00] &= 0xFC;
		
		// apdu header 5 byte
		signMac.update(buf, (short)0x00, (short)0x05);
		// ATC 2 byte
		signMac.update(cardDataBuf, CARD_DATA_OFF_ATC, (short)0x02);		
		// AC 8 byte
		signMac.update(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AUTH_AC, (short)0x08);		
		// exist command data, LC > 4 byte(mac length)
		short p3 = (short)(buf[ISO7816.OFFSET_LC]&0x0FF);
		p3 -= 0x04;

		signMac.sign(buf, ISO7816.OFFSET_CDATA, p3, sessionKey, (short) 0);
		
		if (Util.arrayCompare(sessionKey, (short) 0, buf, (short)(5+p3), (short)0x04) != 0x00) {
			// ISL010 Test Case
			// 发卡行脚本命令MAC错误，发卡行脚本命令计数器计数并设置上次交易发卡行脚本失败指示位
			curTradeConditions[CURRENT_TRADE_CONDITION_OFF_MAC_ERROR] = true;
			cardDataBuf[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] = 0x01;
			incrIssueScriptCmdExcCntr();
			
			macFailedCntr++;
			
			ISOException.throwIt(SW_WRONG_MAC);
		}
		
		if (macFailedCntr != 0x00) {
			macFailedCntr = 0x00;
		}
		
		buf[ISO7816.OFFSET_CLA] = (byte)(cls&0xFB);
		buf[ISO7816.OFFSET_LC] -= 0x04;
	}
	
	/**
	 * decrypt sensitive data
	 * @param buf	sensitive data buffer
	 * @param sOff	sensitive data buffer offset
	 * @param sLen	sensitive data length
	 */
	private void decrypt(byte[] buf, short sOff, short sLen) {
		Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
		Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);
		Util.arrayCopyNonAtomic(sessionKey, (short)0x06, sessionKey, (short)14, (short)0x02);
		sessionKey[14] ^= (byte)0xFF;
		sessionKey[15] ^= (byte)0xFF;
		
		// generate DEK Session Key
		tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_DEK_KEY);
		cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
		
		
		tripleDesKey.setKey(sessionKey, (short)0x00);
		cipherECBDecrypt.doFinal(buf, sOff, sLen, buf, sOff);
	}
	
	/**
	 * issue script trade flow check
	 */
	private void issueScriptTradeFlowCheck() {
		// 在执行一个发卡行脚本命令之前，卡片使用安全报文认证发卡行。
        // 如果卡片收到安全报文校验失败的脚本命令,后续脚本命令不再执行,直接返回状态码“6985”。
		if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_MAC_ERROR]) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		byte tradeState = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE];
		if ((tradeState != TRADE_STATE_CARD_ACTION_ANALYSE) && (tradeState != TRADE_STATE_ON_LINE)) {
			/**
			 * for DUS006 Test
			 * 发卡行认证不成功批准交易联机时，卡片拒绝MAC正确的命令
			 */
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		} else if ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_AUTH_CNTR] > 0x00) 
					&& (abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] == 0x01)) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
	}
	
	/**
	 * get all pre-auth trade money
	 * @param buf	money buffer
	 * @param sOff	money buffer offset
	 */
	private void getAllPreAuthTradeMoney(byte[] buf, short sOff) {
		if (extendPreAuthContext == null) {
			Util.arrayFillNonAtomic(buf, sOff, (short)0x06, (byte)0x00);
			return;
		}
		
		Util.arrayFillNonAtomic(buf, sOff, (short)0x06, (byte)0x00);
		short size = (short)extendPreAuthContext.length;
		for (short i=0x00; i<size; i+=0x09) {
			if (extendPreAuthContext[i] != 0x00) {
				PBOCUtil.arrayDecAdd(buf, sOff, extendPreAuthContext, (short)(i+EXT_PREAUTH_CONTEXT_OFF_MONEY), buf, sOff);
			}
		}				
	}
	
	/**
	 * get current pre-auth trade money
	 * @param buf	money buffer
	 * @param sOff	money buffer offset
	 * @return true is get success, false is get failed
	 */
	private boolean getPreAuthTradeMoney(byte[] buf, short sOff) {
		if (extendPreAuthContext == null) {
			Util.arrayFillNonAtomic(buf, sOff, (short)0x06, (byte)0x00);
			return false;
		}
		
		short size = (short)extendPreAuthContext.length;
		for (short i=0x00; i<size; i+=0x09) {
			if ((extendPreAuthContext[(short)(i+EXT_PREAUTH_CONTEXT_OFF_SFI)] == abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI])
				&& (Util.arrayCompare(extendPreAuthContext, (short)(i+EXT_PREAUTH_CONTEXT_OFF_ID), abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_CUR_ID, (short)0x02) == 0x00)) {
				Util.setShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_CUR_CONTEXT_OFF, i);				
				if (buf != null) {
					Util.arrayCopyNonAtomic(extendPreAuthContext, (short)(i+EXT_PREAUTH_CONTEXT_OFF_MONEY), buf, sOff, (short)0x06);
				}
				
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * get pre-auth context free space
	 * @return true is get success, false is get failed
	 */
	private boolean getPreAuthContextSpace() {
		if (extendPreAuthContext == null) {
			return false;
		}
		
		short size = (short)extendPreAuthContext.length;
		for (short i=0x00; i<size; i+=0x09) {
			if (PBOCUtil.isAllZero(extendPreAuthContext, (short)(i+EXT_PREAUTH_CONTEXT_OFF_ID), (short)0x02)) {
				Util.setShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_CUR_CONTEXT_OFF, i);
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * flush update capp data command cache data
	 */
	private void flushCacheData() {
		short sCacheLen = extendFileCacheCurLen[0x00];
		if (sCacheLen == 0x00) {
			return;
		}
		
		short i = 0x00;
		while (i < sCacheLen) {
			byte fileIndex = extendFileCache[i++];
			short sFileOff = Util.getShort(extendFileCache, i);
			i += 0x02;
			short sDataLen = Util.getShort(extendFileCache, i);
			i += 0x02;
			
			// log file
			if ((fileIndex == (byte)0xFF) && (sFileOff == INVALID_VALUE)) {
				short sRecLen = Util.getShort(extendlogFile, LOG_INFO_OFF_RECLEN);
				short sRecNum = (short)(extendlogFile[LOG_INFO_OFF_RECNUM]&0x0FF);
				short fileSize = (short)((short)(sRecLen*sRecNum) + LOG_INFO_OFF_CONTENT);
				short sOffset = LOG_INFO_OFF_CONTENT;
				short sDstOffset = LOG_INFO_OFF_CONTENT;
				while (sOffset < fileSize) {
					if (PBOCUtil.arrayCompare(extendlogFile, sOffset, extendlogFile, sDstOffset, (short)0x04) == 1) {
						sDstOffset = sOffset;
					}
					
					sOffset += sRecLen;
				}
				
				// increase counter
				PBOCUtil.arrayHexAdd(extendlogFile, sDstOffset, LOG_INCREASE_VAR, (short)0x00, extendFileCache, i, (short)0x04);
				
				if (!PBOCUtil.isAllZero(extendlogFile, sDstOffset, (short)0x04)) {
					sDstOffset += sRecLen;
					if (sDstOffset == fileSize) {
						sDstOffset = LOG_INFO_OFF_CONTENT;
					}
				}
				
				Util.arrayCopyNonAtomic(extendFileCache, i, extendlogFile, sDstOffset, sDataLen);
			} else {
				// normal extend application file
				Util.arrayCopyNonAtomic(extendFileCache, i, (byte[])extAppFiles[fileIndex], (short)(sFileOff+EXT_APP_RECORD_OFF_ID), sDataLen);
			}
			
			i += sDataLen;
		}
		
		extendFileCacheCurLen[0x00] = 0x00;
	}	
	
	/**
	 * cache update capp data command data
	 * @param extFileIndex	extend application file index
	 * @param sFileOffset	extend application file offset
	 * @param data			update data buffer
	 * @param sOff			update data buffer offset
	 * @param sLen			update data length
	 * @param sMaxRecLen	max record length
	 */
	private void cacheUpdateCAPPData(byte extFileIndex, short sFileOffset, byte[] data, short sOff, short sLen) {
		short sCacheLen = extendFileCacheCurLen[0x00];

		// cache space not enough
		if ((short)(sLen+EXTAPP_CACHE_OFF_CONTENT+sCacheLen) > EXTEND_FILE_CACHE_BUF_SIZE) {
			ISOException.throwIt((short)0x6581);
		}		
		
		extendFileCache[sCacheLen++] = extFileIndex;
		sCacheLen = Util.setShort(extendFileCache, sCacheLen, sFileOffset);
		sCacheLen = Util.setShort(extendFileCache, sCacheLen, sLen);
		sCacheLen = Util.arrayCopyNonAtomic(data, sOff, extendFileCache, sCacheLen, sLen);
		
		extendFileCacheCurLen[0x00] = sCacheLen;
	}
	
	/**
	 * put data command process
	 * @param apdu
	 */
	private void onPutData(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x04) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		short sTag = Util.getShort(apduBuf, ISO7816.OFFSET_P1);
		if (sTag == TAG_CAPP_SP_DEDUCTION_MONEY) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		short index = 0x00;
		
		while (true) {
			short sTmp = putDataTags[index];
			if (sTmp == sTag) {
				break;
			} 
			
			if (sTmp == INVALID_VALUE) {
				// 设置上次交易发卡行脚本失败指示位
				cardDataBuf[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] = 0x01;
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			
			index += 0x03;
		}
						
		index++;
		
		apdu.setIncomingAndReceive();
		// check put length
		short sTmp = (short)(apduBuf[ISO7816.OFFSET_LC]&0x0FF);
		short sValueOff = putDataTags[index];
		short sValueLen = putDataTags[(short)(index+0x01)];
		if (sTmp != (short)(sValueLen+0x04)) {
			// 设置上次交易发卡行脚本失败指示位
			cardDataBuf[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] = 0x01;
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		// trade flow check
		issueScriptTradeFlowCheck();
		
		// verify mac
		unWrap(apduBuf);
		incrIssueScriptCmdExcCntr();
	    
		// 第14部分 5.2.7 支持分段扣费押金抵扣功能的特殊处理
	    // 卡片收到发卡行发送的修改分段扣费抵扣限额（DF62）的脚本命令时，如果修改分段扣费抵扣限额的脚本
	    // 中指定的分段扣费抵扣限额（DF62）小于分段扣费已抵扣金额（DF63），则返回6A80；
	    // 否则，用脚本中指定的值完成分段扣费抵扣限额（DF62）的更新。
		switch (sTag) {
		case TAG_CAPP_SP_DEDUCTION_LIMIT:
			if (PBOCUtil.arrayCompare(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, apduBuf, ISO7816.OFFSET_CDATA, (short)0x06) == 0x01) {
				ISOException.throwIt(ISO7816.SW_WRONG_DATA);
			}
			
			// DF62 + 9F77 < 999999999999
			Util.arrayFillNonAtomic(apduBuf, (short)0x10, (short)0x06, (byte)0x99);
			PBOCUtil.arrayDecSub(apduBuf, (short)0x10, cardDataBuf, CARD_DATA_OFF_EC_BALANCE_UPLIMIT, apduBuf, (short)0x10);
			if (PBOCUtil.arrayCompare(apduBuf, ISO7816.OFFSET_CDATA, apduBuf, (short)0x10, (short)0x06) == 0x01) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case TAG_EC_BALANCE_LIMIT:
			// DF62 + 9F77 < 999999999999
			Util.arrayFillNonAtomic(apduBuf, (short)0x10, (short)0x06, (byte)0x99);
			PBOCUtil.arrayDecSub(apduBuf, (short)0x10, cardDataBuf, CARD_DATA_OFF_SP_DEDUCTION_LIMIT, apduBuf, (short)0x10);
			if (PBOCUtil.arrayCompare(apduBuf, ISO7816.OFFSET_CDATA, apduBuf, (short)0x10, (short)0x06) == 0x01) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
			break;
		case TAG_CAPP_SECTION_PURCHASE_APP_ID:			
			if (sExtAppIndicateOff != INVALID_VALUE) {
				contactlessfci[sExtAppIndicateOff] = apduBuf[ISO7816.OFFSET_CDATA];
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_INDICATE] = apduBuf[ISO7816.OFFSET_CDATA];
			}	
			return;	
		}
				
		// 修改电子现金余额时，判断是否超过电子现金余额上限
		if ((sTag == TAG_EC_BALANCE)
			|| (sTag == TAG_EC_SECOND_BALANCE)) {

			JCSystem.beginTransaction();
			
			if (sTag == TAG_EC_BALANCE) {								
				// 更新9F79值若大于DF63值，则将9F79-DF63后若大于9F77则返回6A80
				if (PBOCUtil.arrayCompare(apduBuf, ISO7816.OFFSET_CDATA, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, (short)0x06) == 0x01) {
					// judge 9F79-DF63 > 9F77
					PBOCUtil.arrayDecSub(apduBuf, ISO7816.OFFSET_CDATA, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, apduBuf, (short)0x10);
					if (PBOCUtil.arrayCompare(apduBuf, (short)0x10, cardDataBuf, CARD_DATA_OFF_EC_BALANCE_UPLIMIT, (short)0x06) == 0x01) {
						ISOException.throwIt(ISO7816.SW_WRONG_DATA);
					}
				} else {
					Util.arrayFillNonAtomic(apduBuf, (short)0x10, (short)0x06, (byte)0x00);
				}
				
	    		// 第14部分
	    		// 6.2.8 为了避免圈存后由于预授权完成交易导致卡片内电子现金余额 （ 9F79 ） 超限 ， 卡片在收到
	    		// PUT DATA 指令进行圈存操作时，需要确保电子现金余额上限（ 9F77 ）大于等于 PUT DAT A
	    		// 指令设置的电子现金余额（ 9F79 ） + 卡片未完成的一笔或多笔脱机预授权金额的总和，否
	    		// 则卡片以6A80错误码响应 PUT DATA 指令。
				getAllPreAuthTradeMoney(apduBuf, (short)0x16);
				PBOCUtil.arrayDecAdd(apduBuf, (short)0x16, apduBuf, (short)0x10, apduBuf, (short)0x10);
				
				if (PBOCUtil.arrayCompare(apduBuf, (short)0x10, cardDataBuf, CARD_DATA_OFF_EC_BALANCE_UPLIMIT, (short)0x06) == 0x01) {
					ISOException.throwIt((short)0x6976);
				}
				
	            // 第14部分 5.2.7 支持分段扣费押金抵扣功能的特殊处理
	            // 如果当前电子现金余额（9F79）等于0
	            // 1. 当修改余额脚本中指定的金额大于分段扣费已抵扣金额（DF63），则圈存后的电子现金余额（9F79）
	            // =修改余额脚本中指定的金额-分段扣费已抵扣金额（DF63），同时将分段扣费已抵扣金额（DF63）清零；
	            // 2. 当修改余额脚本中指定的金额小于等于分段扣费已抵扣金额（DF63），则圈存后的分段扣费已抵
	            // 扣金额（DF63）=圈存前分段扣费已抵扣金额（DF63）-修改余额脚本中指定的金额，电子现金余额（9F79）值保持不变；
				if (!PBOCUtil.isAllZero(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, (short)0x06)) {
					// if 0xDF63 < new EC Balance
					if (PBOCUtil.arrayCompare(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, apduBuf, ISO7816.OFFSET_CDATA, (short)0x06) == -1) {
						// new EC Balance -= 0xDF63
						PBOCUtil.arrayDecSub(apduBuf, ISO7816.OFFSET_CDATA, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, apduBuf, ISO7816.OFFSET_CDATA);
						// reset 0xDF63
						Util.arrayFillNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, (short)0x06, (byte)0x00);
					} else {
		                // if 0xDF63 >= new EC Balance
						// 0xDF63 -= new EC Balance
						PBOCUtil.arrayDecSub(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, apduBuf, ISO7816.OFFSET_CDATA, abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY);
						Util.arrayFillNonAtomic(apduBuf, ISO7816.OFFSET_CDATA, (short)0x06, (byte)0x00);
					}
					
					// update DF63
					Util.arrayCopyNonAtomic(abyCurTradeCardData, CARD_DATA_OFF_SP_DEDUCTION_MONEY, cardDataBuf, CARD_DATA_OFF_SP_DEDUCTION_MONEY, (short)0x06);
				}				
			} else {
				if (PBOCUtil.arrayCompare(apduBuf, ISO7816.OFFSET_CDATA, cardDataBuf, CARD_DATA_OFF_EC_SECOND_BALANCE_LIMIE, (short)0x06) == 0x01) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
			}

			byte[] abyCurTradePDOL;
			if (curTradeConditions[CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL]) {
				abyCurTradePDOL = qpbocpdol;				
			} else {
				abyCurTradePDOL = pbocpdol;				
			}
			
			Util.arrayCopy(apduBuf, ISO7816.OFFSET_CDATA, cardDataBuf, sValueOff, sValueLen);			
			updateChargeLog(abyCurTradeCardData, sValueOff, cardDataBuf, sValueOff, sTag, abyCurTradePDOL, apduBuf);						
			Util.arrayCopyNonAtomic(cardDataBuf, sValueOff, abyCurTradeCardData, sValueOff, sValueLen);
						
						
			JCSystem.commitTransaction();
		} else {			
			Util.arrayCopy(apduBuf, ISO7816.OFFSET_CDATA, cardDataBuf, sValueOff, sValueLen);	
		}				
	}
	
	/**
	 * card block command process
	 * @param apdu
	 */
	private void onLockCard(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x84) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		if ((apduBuf[ISO7816.OFFSET_P1] != 0x00)
			|| (apduBuf[ISO7816.OFFSET_P2] != 0x00)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		if (apduBuf[ISO7816.OFFSET_LC] != 0x04) {
			cardDataBuf[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] = 0x01;
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		// trade flow check
		issueScriptTradeFlowCheck();
		
		apdu.setIncomingAndReceive();
		// verify mac
		unWrap(apduBuf);
		
		// fot BCTC Test, if is SWP Card and contactless interface, lock card command execute failed
//		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_INTERFACE] == TRADE_INTERFACE_CONTACTLESS) {
//			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
//		}
		
		JCSystem.beginTransaction();
		
		incrIssueScriptCmdExcCntr();
		cardState[0] = CARD_STATE_LOCKED;
		
		JCSystem.commitTransaction();
	}
	
	/**
	 * application block/unblock command process
	 * @param apdu
	 */
	private void onAppOp(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x84) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		if ((apduBuf[ISO7816.OFFSET_P1] != 0x00)
			|| (apduBuf[ISO7816.OFFSET_P2] != 0x00)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		if (apduBuf[ISO7816.OFFSET_LC] != 0x04) {
			cardDataBuf[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] = 0x01;
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
					
		// trade flow check
		issueScriptTradeFlowCheck();
		
		apdu.setIncomingAndReceive();
		// verify mac
		unWrap(apduBuf);
		
		JCSystem.beginTransaction();
		
		incrIssueScriptCmdExcCntr();
		
		if (apduBuf[ISO7816.OFFSET_INS] == CMD_INS_APP_BLOCK) {
			appState = APP_STATE_LOCKED;
		} else {
			appState = APP_STATE_ISSUED;
		}
				
		JCSystem.commitTransaction();
	}
	
	/**
	 * external auth commmand process
	 * @param apdu
	 */
	private void onExternalAuth(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		if ((apduBuf[ISO7816.OFFSET_P1] != 0x00)
			|| (apduBuf[ISO7816.OFFSET_P2] != 0x00)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		if (apduBuf[ISO7816.OFFSET_LC] != 0x0A) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		apdu.setIncomingAndReceive();
		
		// trade flow check
		if ((externalAuthFailedCntr == MAX_FAILED_COUNTER)
			|| (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] != TRADE_STATE_CARD_ACTION_ANALYSE)) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		/**
		 * 如果在当前交易里，收到过外部认证命令:
		 * 1. 设置上次交易指示器中"发卡行认证失败"指示位
		 * 2. 设置CVR中"发卡行认证执行但失败"指示位
		 */
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_AUTH_CNTR] > 0x00) {
			abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] = 0x01;
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_ISSUE_AUTH_EXEC_FAILED);
			
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_AUTH_CNTR]++;
		short sARCOff = (short)(ISO7816.OFFSET_CDATA+0x08);
		
		Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x10, (byte)0x00);
		Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);
		Util.arrayCopyNonAtomic(sessionKey, (short)0x06, sessionKey, (short)14, (short)0x02);
		sessionKey[14] ^= (byte)0xFF;
		sessionKey[15] ^= (byte)0xFF;
		
		// generate APP Session Key
		tripleDesKey.setKey(paramBuf, PBOC_PARAM_OFF_APP_KEY);
		cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x10, sessionKey, (short)0x00);
		
		tripleDesKey.setKey(sessionKey, (short) 0x00);
		
		// 1. X：=(ARC||‘00’||‘00’||‘00’||‘00’||‘00’||‘00’)。 
		// 2. 计算Y：=ARQC⊕X
		// 3. 计算ARPC		
		Util.arrayCopyNonAtomic(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AUTH_AC, apduBuf, (short)0x10, (short)0x08);
		apduBuf[0x10] ^= apduBuf[sARCOff];
		apduBuf[0x11] ^= apduBuf[(short)(sARCOff+0x01)];									
		
		cipherECBEncrypt.doFinal(apduBuf, (short)0x10, (short)0x08, apduBuf, (short)0x10);
		
		/**
		 * 发卡行认证失败：
		 * 1. 设置上次交易指示器中"发卡行认证失败"指示位
		 * 2. 设置 CVR 中“发卡行认证执行但失败”位
		 */	
		if (Util.arrayCompare(apduBuf, (short)0x10, apduBuf, ISO7816.OFFSET_CDATA, (short)0x08) != 0x00) {
			abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] = 0x01;
			PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_ISSUE_AUTH_EXEC_FAILED);
			
			externalAuthFailedCntr++;
			
			ISOException.throwIt(SW_EXTERNAL_AUTH_FAILED);
		}
		
		if (externalAuthFailedCntr != 0x00) {
			externalAuthFailedCntr = 0x00;
		}
		
		// 获得发卡行授权响应码
		Util.arrayCopyNonAtomic(apduBuf, sARCOff, abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXTERNAL_AUTH_CODE, (short)0x02);
		// 清除发卡行认证失败指示位
		abyCurTradeCardData[CARD_DATA_OFF_LAST_TRADE_ISSUE_AUTH_FAILED] = 0x00;
	}
	
	/**
	 * internal auth command process
	 * @param apdu
	 */
	private void onInternalAuth(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x00) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		if ((apduBuf[ISO7816.OFFSET_P1] != 0x00)
			|| (apduBuf[ISO7816.OFFSET_P2] != 0x00)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		short p3 = (short)(apduBuf[ISO7816.OFFSET_LC]&0x0FF);
		short ddolValueLen = (short)(paramBuf[PBOC_PARAM_OFF_DDOLVALUE_LEN]&0x0FF);
		if (p3 != ddolValueLen) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		apdu.setIncomingAndReceive();				
		
		// trade flow check
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] != TRADE_STATE_APP_INIT) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		// not support DDA
		if (!PBOCUtil.isBitSet(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_AIP, AIP_SUPPORT_OFF_DDA)) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		// 1. 设置 CVR 中脱机动态数据认证执行位
		PBOCUtil.setBit(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_CVR, CVR_OFF_DDA_EXEC);
		// 2. 生成标准DDA动态签名
		short sLen = (short)ddaTemplate.length;
		if (sLen > 253) {
			return;
		}
		
		msgDigest.update(ddaTemplate, DDA_OFF_SIGN_FORMAT, (short)(DDA_OFF_IC_DATA_DIGIT-DDA_OFF_SIGN_FORMAT));
		msgDigest.update(cardDataBuf, CARD_DATA_OFF_ATC, (short)0x02);
		msgDigest.update(ddaTemplate, DDA_OFF_PADDING_BB, (short)(sLen-DDA_OFF_PADDING_BB-21));
		msgDigest.update(apduBuf, ISO7816.OFFSET_CDATA, p3);
		
		Util.arrayCopyNonAtomic(ddaTemplate, (short)0x00, apduBuf, (short)0x00, sLen);
		msgDigest.doFinal(apduBuf, (short)0x00, (short)0x00, apduBuf, (short)(sLen-21));

		// replace ATC
		Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, apduBuf, DDA_OFF_IC_DATA_DIGIT, (short)0x02);
		
		cipherRSA.doFinal(apduBuf, (short)0x00, sLen, apduBuf, ISO7816.OFFSET_CDATA);
		
		sLen = PBOCUtil.appendTLV((short)0x80, apduBuf, ISO7816.OFFSET_CDATA, sLen, apduBuf, (short)0x00);
		
		apdu.setOutgoingAndSend((short)0x00, sLen);
	}
	
	/**
	 * update record command process
	 * @param apdu
	 */
	private void onUpdateRecord(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x04) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// trade flow check
		issueScriptTradeFlowCheck();
		
		apdu.setIncomingAndReceive();		
		// verify mac
		unWrap(apduBuf);
		
		// 增加发卡行脚本执行个数
		incrIssueScriptCmdExcCntr();
		
		byte sfi = (byte)((byte)(apduBuf[ISO7816.OFFSET_P2]>>0x03)&0x1F);
		byte recNo = apduBuf[ISO7816.OFFSET_P1];
		
		short dgi = Util.makeShort(sfi, recNo);
		
		short index;
		short sTmp = 0x00;
		for (index=0x00; index<RECORD_OBJECT_SIZE; index++) {
			sTmp = recordMap[index];
			
			if (sTmp == INVALID_RECORD_MAP_VALUE) {
				break;
			}
			
			if (sTmp == dgi) {				
				break;
			}			
		}
		
		if (sTmp != dgi) {			
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}
		
		byte[] record = (byte[])recordObj[index];
		short sLen = (short)record.length;
		short p3 = (short)(apduBuf[ISO7816.OFFSET_LC]&0x0FF);
		if (p3 > sLen) {
			cardDataBuf[CARD_DATA_OFF_LAST_TRADE_ISSUE_SCRIPT_RUN_FAILED] = 0x01;			
			ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		}
		
		Util.arrayCopy(apduBuf, ISO7816.OFFSET_CDATA, record, (short)0x00, p3);
	}
	
	/**
	 * change and unblock PIN command process
	 * @param apdu
	 */
	private void onChangeUnBlockPIN(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x84) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		if (apduBuf[ISO7816.OFFSET_P1] != 0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		short p2 = (short)(apduBuf[ISO7816.OFFSET_P2]&0x0FF);
		byte p3 = 0x00;
		if (p2 > 0x02) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		} else if (p2 == 0x00) {
			p3 = 0x04;
		} else {
			p3 = 0x14;
		}
		
		if (p3 != apduBuf[ISO7816.OFFSET_LC]) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		// trade flow check
		issueScriptTradeFlowCheck();
		
		apdu.setIncomingAndReceive();		
		// verify mac
		unWrap(apduBuf);
		
		JCSystem.beginTransaction();
		incrIssueScriptCmdExcCntr();
		
		paramBuf[PBOC_PARAM_OFF_PIN_LEFT_CNTR] = paramBuf[PBOC_PARAM_OFF_PIN_MAX_CNTR];
		// change PIN Value
		if (p2 != 0x00) {
			decrypt(apduBuf, ISO7816.OFFSET_CDATA, (short)0x10);
			if (p2 == 0x01) {
				Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x08, (byte)0x00);
				Util.arrayCopyNonAtomic(paramBuf, PBOC_PARAM_OFF_PIN_VALUE, sessionKey, (short)0x00, (short)0x06);
				// D4 = 将PIN值中的FF填充转换为0x00
				short i = 0x06;
				while (i > 0x00) {
					short sOff = (short)(i-0x01);
					if (sessionKey[sOff] == (byte)0xFF) {
						sessionKey[sOff] = 0x00;
					} else if ((byte)(sessionKey[sOff]&0x0F) == (byte)0x0F) {
						sessionKey[sOff] &= (byte)0xF0;
					} else {
						break;
					}
					
					i--;
				}
				
				// D4 xor D = D3
				PBOCUtil.arrayXor(apduBuf, (short)(ISO7816.OFFSET_CDATA+0x01), sessionKey, (short)0x00, (short)0x08);
			}
			
			// D1 = "00 00 00 00" +	ENC UDK-A的最右边4个字节(DEK)
			Util.arrayCopyNonAtomic(paramBuf, PBOC_PARAM_OFF_DEK_KEY, sessionKey, (short)0x00, (short)0x08);
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x04, (byte)0x00);
			
			// D3 XOR D1 = D2
			PBOCUtil.arrayXor(apduBuf, (short)(ISO7816.OFFSET_CDATA+0x01), sessionKey, (short)0x00, (short)0x08);
			
			p3 = (byte) (apduBuf[(short)(ISO7816.OFFSET_CDATA+0x01)]&0x0F);
			byte cntr = (byte)(p3/2);
			if ((p3%2) != 0x00) {
				cntr++;
			}
			
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x06, (byte)0xFF);
			Util.arrayCopyNonAtomic(apduBuf, (short)(ISO7816.OFFSET_CDATA+0x02), sessionKey, (short)0x00, cntr);
			Util.arrayCopy(sessionKey, (short)0x00, paramBuf, PBOC_PARAM_OFF_PIN_VALUE, (short)0x06);
		}
		
		JCSystem.commitTransaction();
	}
	
	/**
	 * get response command process
	 * @param apdu
	 */
	private void onGetResponse(APDU apdu) {
		short sLen = getResponseLen;
		if (sLen == 0x00) {
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		getResponseLen = 0x00;
		
		byte[] apduBuf = apdu.getBuffer();
		if (apduBuf[ISO7816.OFFSET_CLA] != 0x00) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		byte[] fci;
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_INTERFACE] == TRADE_INTERFACE_CONTACT) {
			fci = contactfci;
		} else {
			fci = contactlessfci;
		}
		
		Util.arrayCopyNonAtomic(fci, (short)0x00, apduBuf, (short)0x00, sLen);
		apdu.setOutgoingAndSend((short)0x00, sLen);
	}
	
	/**
	 * select command process
	 * @param apduBuf
	 */
	private void onSelect(byte[] apduBuf) {
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != 0x00) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check p1 && p2
		byte p2 = apduBuf[ISO7816.OFFSET_P2];
		byte p3 = apduBuf[ISO7816.OFFSET_LC];
		
		if ((apduBuf[ISO7816.OFFSET_P1] != 0x04)
			|| (p2 < 0x00)
			|| (p2 > 0x02)
			|| (p2 == 0x01)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		if (p3 < 0x05 || p3 > 0x10) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		
		ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
	}
	
	/**
	 * append record command process
	 * @param apdu
	 */
	private void onAppendRecord(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x04) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check p1
		if (apduBuf[ISO7816.OFFSET_P1] != 0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		// check p2
		byte p2 = apduBuf[ISO7816.OFFSET_P2];
		byte sfi = (byte)((byte)(apduBuf[ISO7816.OFFSET_P2]>>0x03)&0x1F);
		if (((byte)(p2&0x07)>0x01)
			|| (sfi == 0x00)
			|| (sfi == 0x1F)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		short p3 = (short)(apduBuf[ISO7816.OFFSET_LC]&0x0FF);
		if (p3 < 0x05) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
				
		short index = findExtendFile(sfi);
		if (index == INVALID_VALUE) {
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		}
		
		// if not found then find extend application log file
		byte[] file = (byte[])extAppFiles[index];
		if (file[EXT_APP_FILE_OFF_TYPE] == EXT_APP_FILE_TYPE_LOG_FILE) {
			if (extendlogFile != null) {
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			}
		} else {
			// check p3
			if (p3 < 0x17) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}			
		}
		apdu.setIncomingAndReceive();
		
		tripleDesKey.setKey(file, EXT_APP_FILE_OFF_OPEN_KEY);
		Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x08, (byte)0x00);
		Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);				
		
		apduBuf[ISO7816.OFFSET_CLA] &= (byte)0xFC;
		PBOCUtil.arrayXor(sessionKey, (short)0x00, apduBuf, (short)0x00, (short)0x08);		
		signMac.update(sessionKey, (short)0x00, (short)0x08);		
		signMac.sign(apduBuf, (short)0x08, (short)(p3-0x07), sessionKey, (short)0x00);
		// mac verify failed
		if (Util.arrayCompare(apduBuf, (short)(p3+0x01), sessionKey, (short)0x00, (short)0x04) != 0x00) {
			ISOException.throwIt((short)0x6988);
		}
				
		p3 -= 0x04;
		apduBuf[ISO7816.OFFSET_LC] = (byte)p3;
		
		// command data is: 16字节记录修改密钥（由应用开通密钥加密）+新增的记录内容
		// so record len = iso_p3 - 0x10
		cipherECBDecrypt.doFinal(apduBuf, ISO7816.OFFSET_CDATA, (short)0x10, apduBuf, ISO7816.OFFSET_CDATA);
		
		JCSystem.beginTransaction();
		
		short sRecLen = (short) (p3 - 0x10);
		// open extend application log file record
		if (file[EXT_APP_FILE_OFF_TYPE] == EXT_APP_FILE_TYPE_LOG_FILE) {
			short logFileRecLen = (short)(file[EXT_APP_FILE_OFF_MAX_RECLEN]&0x0FF);	
			if (sRecLen > logFileRecLen) {
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			short sRecNum = (short)(Util.getShort(file, EXT_APP_FILE_OFF_MAX_SIZE)/logFileRecLen);
			// record sequence number, 4 byte
			logFileRecLen = (short)(sRecLen+0x04);
			short newFileSize = (short)(logFileRecLen*sRecNum);			
			byte[] logFile = new byte[(short)(LOG_INFO_OFF_CONTENT+newFileSize+0x10)];
			logFile[LOG_INFO_OFF_SFI] = sfi;
			Util.setShort(logFile, LOG_INFO_OFF_RECLEN, logFileRecLen);
			logFile[LOG_INFO_OFF_RECNUM] = (byte)sRecNum;
						
			extendlogFile = file = logFile;
									
			// 记录修改密钥
			Util.arrayCopyNonAtomic(apduBuf, ISO7816.OFFSET_CDATA, file, (short)(file.length-0x10), (short)0x10);
						
			file[(short)(LOG_INFO_OFF_CONTENT+0x03)] = 0x01;
			Util.arrayCopyNonAtomic(apduBuf, (short)(ISO7816.OFFSET_CDATA+0x10), file, (short)(LOG_INFO_OFF_CONTENT+0x04), sRecLen);						
		} else {
			short fileSize = Util.getShort(file, EXT_APP_FILE_OFF_MAX_SIZE);
			short curSize = Util.getShort(file, EXT_APP_FILE_OFF_CUR_SIZE);
			if ((short)(curSize+sRecLen) > fileSize) {
				ISOException.throwIt((short)0x6A84);
			}
			
			curSize += sRecLen;
			
			short oldfileSize = (short) file.length;
			// 0x11 == record length(1 byte) +  key value(0x10)
			fileSize = (short)(oldfileSize + 0x11 + sRecLen);
			
			byte[] newFile = new byte[fileSize];
			Util.arrayCopyNonAtomic(file, (short)0x00, newFile, (short)0x00, oldfileSize);
			
			// write current file size
			Util.setShort(newFile, EXT_APP_FILE_OFF_CUR_SIZE, curSize);
			// write length
			newFile[oldfileSize++] = (byte)(0x10 + sRecLen);
			// write update key
			oldfileSize = Util.arrayCopyNonAtomic(apduBuf, ISO7816.OFFSET_CDATA, newFile, oldfileSize, (short)0x10);
			// write record content
			Util.arrayCopyNonAtomic(apduBuf, (short)(ISO7816.OFFSET_CDATA+0x10), newFile, oldfileSize, sRecLen);
			
			extAppFiles[index] = newFile;		
		}
		
		if (extendFileCache == null) {
			if (RAM_CACHE) {
				if (FUNCTION_FOR_TIANYU) {
					extendFileCache = JCSystem.makeTransientByteArray(EXTEND_FILE_CACHE_BUF_SIZE, JCSystem.CLEAR_ON_RESET);
				} else {
					extendFileCache = JCSystem.makeTransientByteArray(EXTEND_FILE_CACHE_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
				}
			} else {
				extendFileCache = new byte[EXTEND_FILE_CACHE_BUF_SIZE];
			}
			
			if (FUNCTION_FOR_TIANYU) {
				extendFileCacheCurLen = JCSystem.makeTransientShortArray((short)0x01, JCSystem.CLEAR_ON_RESET);
			} else {
				extendFileCacheCurLen = JCSystem.makeTransientShortArray((short)0x01, JCSystem.CLEAR_ON_DESELECT);
			}
		}
				
		JCSystem.commitTransaction();
	}
	
	/**
	 * get trans prove command process
	 * @param apdu
	 */
	private void onGetTransProve(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x80) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check p1 && p2
		if (apduBuf[ISO7816.OFFSET_P1] != 0x00
			|| apduBuf[ISO7816.OFFSET_P2] != 0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		if (apduBuf[ISO7816.OFFSET_LC] != 0x02) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		apdu.setIncomingAndReceive();
		
		// 所需TC不可用
		if (Util.arrayCompare(abyCurTradeCardData, CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO, apduBuf, ISO7816.OFFSET_CDATA, (short)0x02) != 0x00) {
			ISOException.throwIt((short)0x9406);
		}
		
		Util.arrayCopyNonAtomic(abyCurTradeCardData, (short)(CARD_DATA_OFF_EXT_APP_LASTTRADE_INFO+0x02), apduBuf, (short)0x00, (short)0x08);
		
		apdu.setOutgoingAndSend((short)0x00, (short)0x08);
	}		
	
	/**
	 * find extend application record by sfi with ID
	 * @param type	01 find first else find next
	 * @param sfi	extend application file sfi
	 * @param id	record ID
	 */
	private void findExtAppFileNextRecord(byte type, byte sfi, short id) {
		byte index = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX];
		short sOffset = Util.getShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_FILE_OFFSET);
		byte[] file = null;
		// 读取同一区号的下一条记录
		if ((byte)(type&0x01) == 0x01) {
			if (index == INVALID_VALUE) {
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			}
			file = (byte[])extAppFiles[index];
			if (file[EXT_APP_FILE_OFF_SFI] != sfi) {
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);	
			}
			if (sOffset == INVALID_VALUE) {
				ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
			}
			
			// get next record offset
			sOffset = (short)((short)(file[sOffset]&0x0FF) + 0x01 + sOffset);
		} else {
			short size = (short)(extAppFiles.length);
			index = 0x00;
			while (index < size) {
				file = (byte[])extAppFiles[index];
				if (file[EXT_APP_FILE_OFF_SFI] == sfi) {
					break;
				}
				
				index++;
			}
			
			if (index == size) {
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			}
			
			sOffset = EXT_APP_FILE_OFF_CONTENT;
		}
		
		// get current file end offset
		short sFileLen = (short)file.length;
		while (sOffset < sFileLen) {
			// record ID match
			if (Util.getShort(file, (short)(sOffset+EXT_APP_RECORD_OFF_ID)) == id) {
				abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX] = index;
				Util.setShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_FILE_OFFSET, sOffset);
				return;
			}
			
			// get next record offset
			sOffset = (short)((short)(file[sOffset]&0x0FF) + 0x01 + sOffset);
		}
		
		// clear info
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX] = INVALID_VALUE;
		Util.setShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_FILE_OFFSET, INVALID_VALUE);
		
		ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
	}
	
	/**
	 * read capp data command process
	 * @param apdu
	 */
	private void onReadCAPPData(APDU apdu) {
		byte[] apduBuf = apdu.getBuffer();
		
		// check class
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x80) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check p1
		if (apduBuf[ISO7816.OFFSET_P1] != 0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		byte p2 = apduBuf[ISO7816.OFFSET_P2];
		byte sfi = (byte)((byte)(p2>>0x03)&0x1F);
		if (((byte)(p2&0x07) > 0x01)
			|| (sfi == 0x00)
			|| (sfi == 0x1F)) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		switch (apduBuf[ISO7816.OFFSET_LC]) {
		case 0x02:
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_SUPPORT_RMAC] = 0x00;
			break;
		case 0x0A:
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_SUPPORT_RMAC] = 0x01;			
			break;
		default:
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		apdu.setIncomingAndReceive();
		
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_SUPPORT_RMAC] == 0x01) {
			Util.arrayCopyNonAtomic(apduBuf, (short)0x07, sessionKey, (short)0x00, (short)0x08);
		}
		
		short id = Util.getShort(apduBuf, ISO7816.OFFSET_CDATA);
		// find record
		findExtAppFileNextRecord(p2, sfi, id);
		
		byte[] file = (byte[])extAppFiles[abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX]];
		short sOffset = Util.getShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_FILE_OFFSET);
		
		// get record len, not include key value and L
		short sLen = (short) ((short)(file[sOffset]&0x0FF) - 0x10);
		Util.arrayCopyNonAtomic(file, (short)(sOffset+EXT_APP_RECORD_OFF_ID), apduBuf, (short)0x00, sLen);
		
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_SUPPORT_RMAC] == 0x01) {
			tripleDesKey.setKey(file, (short)(sOffset+EXT_APP_RECORD_OFF_MNG_KEY));
			if (sLen > 0x08) {
				PBOCUtil.arrayXor(sessionKey, (short)0x00, apduBuf, (short)0x00, (short)0x08);
				
				signMac.update(sessionKey, (short)0x00, (short)0x08);
				signMac.sign(apduBuf, (short)0x08, (short)(sLen-0x08), apduBuf, sLen);
			} else {
				PBOCUtil.arrayXor(sessionKey, (short)0x00, apduBuf, (short)0x00, sLen);
				sessionKey[sLen] ^= (byte)0x80;
				
				cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x08, apduBuf, sLen);
			}
			sLen += 0x04;
		}
	
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI] = sfi;
		Util.setShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_CUR_ID, id);
		curTradeConditions[CURRENT_TRADE_CONDITION_OFF_EXT_TRADE_RESULT] = false;
		
		apdu.setOutgoingAndSend((short)0x00, sLen);
	}
	
	/**
	 * update capp data cache command process
	 * @param apdu
	 */
	private void onUpdateCAPPDataCache(APDU apdu) {				
		if ((abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_TYPE] == EXTEND_APP_TRADE_TYPE_NOT_SUPPORT)
			|| ((byte)(abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_CVR]&CVR_1ST_GEN_AC_MASK) != CVR_1ST_GEN_AC_RETURN_TC)) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		// check class
		byte[] apduBuf = apdu.getBuffer();
		if ((byte)(apduBuf[ISO7816.OFFSET_CLA]&0xFC) != (byte)0x84) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		// check p1
		if (apduBuf[ISO7816.OFFSET_P1] != 0x00) {
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
		}
		
		// check p2
		byte p2 = apduBuf[ISO7816.OFFSET_P2];
		byte sfi = (byte)((byte)(p2>>0x03)&0x1F);
		if (((byte)(p2&0x07) > 0x01)
			|| (sfi == 0x00)
			|| (sfi == 0x1F)) {
			ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		}
		
		// check p3
		short p3 = (short)(apduBuf[ISO7816.OFFSET_LC]&0x0FF);
		if (p3 < 0x05) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		}
		
		apdu.setIncomingAndReceive();
		
	    // 检查扩展应用专用文件的使用条件，若该命令的前续命令不是GPO命令或另一条UPDATECAPPDATACACHE命令，
	    // 则回送状态码‘6985’(使用条件不满足)。
		byte lastCmdIns = abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_LAST_CMD_INS];
		if ((lastCmdIns != CMD_INS_GPO)
			&& (lastCmdIns != CMD_INS_UPDATE_CAPP_DATA)) {
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
		}
		
		boolean bIsLogFile = false;
		short sRecLen;
		short sOffset;
		short id = 0x00;
		byte[] file;
		if ((extendlogFile != null) && (extendlogFile[LOG_INFO_OFF_SFI] == sfi)) {
			sOffset = 0x00;
			sRecLen = Util.getShort(extendlogFile, LOG_INFO_OFF_RECLEN);
			sRecLen -= 0x04;
			
			// get extend application log master key value
			tripleDesKey.setKey(extendlogFile, (short) (extendlogFile.length-0x10));
						
			bIsLogFile = true;	 
		} else {
			id = Util.getShort(apduBuf, ISO7816.OFFSET_CDATA);
			findExtAppFileNextRecord(p2, sfi, id);
			
			file = (byte[])extAppFiles[abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX]];
			sOffset = Util.getShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_FILE_OFFSET);
			
			// get record len, not include key value and L
			sRecLen = (short) ((short)(file[sOffset]&0x0FF) - 0x10);
			tripleDesKey.setKey(file, (short)(sOffset+EXT_APP_RECORD_OFF_MNG_KEY));
		}

		Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x08, (byte)0x00);
		Util.arrayCopyNonAtomic(cardDataBuf, CARD_DATA_OFF_ATC, sessionKey, (short)0x06, (short)0x02);				
		
		apduBuf[ISO7816.OFFSET_CLA] &= (byte)0xFC;
		PBOCUtil.arrayXor(sessionKey, (short)0x00, apduBuf, (short)0x00, (short)0x08);
		signMac.update(sessionKey, (short)0x00, (short)0x08);		
		signMac.sign(apduBuf, (short) 0x08, (short)(p3-0x07), sessionKey, (short)0x00);
		// mac verify failed
		if (Util.arrayCompare(apduBuf, (short)(p3+0x01), sessionKey, (short)0x00, (short)0x04) != 0x00) {
			ISOException.throwIt((short)0x6988);
		}		
		// backup CMAC
		Util.arrayCopyNonAtomic(apduBuf, (short)(p3+0x01), sessionKey, (short)0x04, (short)0x04);
		p3 -= 0x04;
		
	    // 检查命令中的数据域长度是否大于扩展应用专用文件中相应记录的长度。如果大于，则回送状态码‘6A84’（文件中存储空间不够）；
	    // 如果小于，则回送状态‘6A80’(数据域不正确)。终端应终止此次扩展应用交易。
		if (p3 > sRecLen) {
			ISOException.throwIt(ISO7816.SW_FILE_FULL);
		} else if ((!bIsLogFile) && (p3 < sRecLen)) {
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		}
		
		// cache record
		if (bIsLogFile) {
			// log record counter 4 byte
			cacheUpdateCAPPData((byte)0xFF, INVALID_VALUE, apduBuf, (short)0x01, (short)(p3+0x04));
		} else {
			cacheUpdateCAPPData(abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_FILE_INDEX], sOffset, apduBuf, ISO7816.OFFSET_CDATA, p3);
		}
				
	    // 第14部分 6.2.4 读取卡片数据内容
	    // 在最后一个记录被成功读取后，卡片检测当前UPDATECAPPDATACACHE所更新的CAPP
	    // 记录是否与最后一条READCAPPDATA的CAPP记录一致（即相同SFI的扩展应用文件下相
	    // 同ID的记录），且更新成功。如果是，卡片同步完成脱机预授权金额的处理、电子现金余额
	    // 的更新和CAPP记录的实际更新，并保存本次交易应用密文（TC），交易正常完成；如果否，
	    // 卡片在最后一条记录时，返回‘6974’，交易失败
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_EXT_APP_CUR_SFI] == sfi
			&& (Util.getShort(abyPBOCTradeSession, TRADE_SESSION_DATA_OFF_EXT_APP_CUR_ID) == id)) {
			curTradeConditions[CURRENT_TRADE_CONDITION_OFF_EXT_TRADE_RESULT] = true;
		}
						
		if (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_SUPPORT_RMAC] == 0x01) {
	        // 使用行业应用管理密钥对响应报文的状态码进行加密生成
	        // 初始向量为‘00’||‘00’||‘00’||‘00’||命令报文数据域中的MAC			
			Util.arrayFillNonAtomic(sessionKey, (short)0x00, (short)0x04, (byte)0x00);
			sessionKey[0x00] = (byte)0x90;
			sessionKey[0x02] = (byte)0x80;
			cipherECBEncrypt.doFinal(sessionKey, (short)0x00, (short)0x08, apduBuf, (short)0x00);			
			
			apdu.setOutgoingAndSend((short)0x00, (short)0x04);
		}		
	}
	
	private void varInit() {
		if (extendFileCache != null) {
			Util.arrayFillNonAtomic(extendFileCache, (short)0x00, EXTEND_FILE_CACHE_BUF_SIZE, (byte)0x00);
			extendFileCacheCurLen[0x00] = 0x00;
		}
		
		for (short i=0x00; i<CURRENT_TRADE_CONDITION_SIZE; i++) {
			curTradeConditions[i] = false;
		}		
	}
	
	/**
	 * Called by the Java Card runtime environment to process an incoming APDU command. 
	 * An applet is expected to perform the action requested and return response data if any to the terminal.
	 */
	public void process(APDU apdu) throws ISOException {
		// card lock and trade finished
		if ((CARD_STATE_LOCKED == cardState[0])
		    && (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] == TRADE_STATE_INVALID)) {
			ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
		}
		
		byte[] apduBuf = apdu.getBuffer();
				
		if (selectingApplet()) {			
			if ((apduBuf[ISO7816.OFFSET_CLA]&0xFC) != 0x00) {
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			}									
			
			if (FUNCTION_FOR_TIANYU) {
				varInit();
			}
			
			// contact
			byte tradeInterface;		
			byte[] abyFCI;
			
			if (APDU.getProtocol() == 0x00) {
				tradeInterface = TRADE_INTERFACE_CONTACT;
				abyFCI = contactfci;
				curTradeConditions[CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL] = false;
				//abyCurTradePDOL = pbocpdol;
				//abyCurTradePDOLValue = pbocpdolValue;
			} else {
				if (contactlessfci == null) {
					abyFCI = contactfci;
					tradeInterface = TRADE_INTERFACE_CONTACT;
					
					curTradeConditions[CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL] = false;
					//abyCurTradePDOL = pbocpdol;					
					//abyCurTradePDOLValue = pbocpdolValue;
				} else {
					abyFCI = contactlessfci;
					tradeInterface = TRADE_INTERFACE_CONTACTLESS;
					curTradeConditions[CURRENT_TRADE_CONDITION_OFF_QPBOCPDOL] = true;
					//abyCurTradePDOL = qpbocpdol;
					//abyCurTradePDOLValue = qpbocpdolValue;
				}
			}
			
			if (abyFCI == null) {
				return;
			}
						
			// set trade life cycle
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] = TRADE_STATE_APP_SELECT;
			// set trade interface
			abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_TRADE_INTERFACE] = tradeInterface;
			// init extend trade flag
			curTradeConditions[CURRENT_TRADE_CONDITION_OFF_EXT_TRADE_RESULT] = true;
			
			short sLen = (short) abyFCI.length;
			Util.arrayCopyNonAtomic(abyFCI, (short)0x00, apduBuf, (short)0x00, sLen);
			
			// read card data
			Util.arrayCopyNonAtomic(cardDataBuf, (short)0x00, abyCurTradeCardData, (short)0x00, CURRENT_TRADE_CARD_DATA_BUF_SIZE);
			
			// app lock
			if (appState == APP_STATE_LOCKED
				|| appState == APP_STATE_FOREVER_LOCKED) {
				if (tradeInterface == TRADE_INTERFACE_CONTACT) {						
					getResponseLen = sLen;	
				} else {
					apdu.setOutgoingAndSend((short) 0x00, sLen);						
				}
				
				if (appState == APP_STATE_FOREVER_LOCKED) {
					abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] = TRADE_STATE_INVALID;
				}
				
				ISOException.throwIt(SW_SELECTED_FILE_DEACTIVED);
			}
			
			apdu.setOutgoingAndSend((short) 0x00, sLen);
			
			return;
		}
		
		byte ins = apduBuf[ISO7816.OFFSET_INS];
		SecureChannel sc;
		
		if ((Util.getShort(backRecord, (short)0x00) != 0x00) && (ins != CMD_INS_READ_RECORD) && (abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_STATE] == TRADE_STATE_APP_SELECT)) {
			Util.setShort(backRecord, (short)0x00, (byte)0x00);
		}
		
		switch (ins) {
		case CMD_INS_READ_RECORD:
			onReadRecord(apdu);
			break;
		case CMD_INS_GPO:
			onGPO(apdu);
			break;
		case CMD_INS_READ_CAPP_DATA:
			onReadCAPPData(apdu);
			break;
		case CMD_INS_UPDATE_CAPP_DATA:
			onUpdateCAPPDataCache(apdu);
			break;
		case CMD_INS_GET_TRANS_PROVE:
			onGetTransProve(apdu);
			break;
		case CMD_INS_GET_RSP:
			onGetResponse(apdu);
			break;
		case CMD_INS_UPDATE_RECORD:
			onUpdateRecord(apdu);
			break;
		case CMD_INS_GENERATE_AC:
			onGenerateAC(apdu);
			break;
		case CMD_INS_SELECT:
			onSelect(apduBuf);
			break;
		case CMD_INS_GET_DATA:
			onGetData(apdu);
			break;
		case CMD_INS_PUT_DATA:
			onPutData(apdu);
			break;			
		case CMD_INS_VERIFY_PIN:
			onVerifyPIN(apdu);
			break;
		case CMD_INS_CHANGE_UNBLOCK_PIN:
			onChangeUnBlockPIN(apdu);
			break;
		case CMD_INS_INTERN_AUTH:
			onInternalAuth(apdu);
			break;
		case CMD_INS_CARD_LOCK:
			onLockCard(apdu);
			break;
		case CMD_INS_APP_BLOCK:
			onAppOp(apdu);
			break;
		case CMD_INS_APP_UBLOCK:
			onAppOp(apdu);
			break;
		case CMD_INS_STORE_DATA:
			//store data in INIT, append record in ISSUED
			if (appState == APP_STATE_ISSUED) {
				onAppendRecord(apdu);				
			} else {
				sc = GPSystem.getSecureChannel();
				if (sc.getSecurityLevel() == SecureChannel.NO_SECURITY_LEVEL) {
					ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
				}
				apdu.setIncomingAndReceive();
				
				sc.unwrap(apduBuf, (short) 0x00, (short) (0x05+(short)(apduBuf[ISO7816.OFFSET_LC]&0x00FF)));
				onStoreData(sc, apduBuf);
			}
			break;
		default:
			if (appState == APP_STATE_INIT) {
				sc = GPSystem.getSecureChannel();
				short sLen = sc.processSecurity(apdu);
				if (sLen > 0x00) {
					apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, sLen);
				}
			} else {
				if (apduBuf[ISO7816.OFFSET_INS] == CMD_INS_EXTERN_AUTH) {
					onExternalAuth(apdu);	
				} else {
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				}
			}
		}
		
		abyPBOCTradeSession[TRADE_SESSION_DATA_OFF_LAST_CMD_INS] = ins;
	}

	/**
	 * Called by the Java Card runtime environment to inform this applet instance that the Applet Deletion Manager has been requested to delete it. 
	 * This method is invoked by the Applet Deletion Manager before any dependency checks are performed. 
	 * The Applet Deletion Manager will perform dependency checks upon return from this method. 
	 * If the dependency check rules disallow it, the applet instance will not be deleted.
	 */
	public void uninstall() {
		JCSystem.beginTransaction();		
		
		if (appState != APP_STATE_INIT) {
			curPersoAppletNum--;
		}		
		maxAppletNum--;
		
		JCSystem.commitTransaction();
	}
}
