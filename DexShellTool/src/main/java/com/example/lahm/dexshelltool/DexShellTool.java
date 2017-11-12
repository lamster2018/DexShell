package com.example.lahm.dexshelltool;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.Adler32;

/**
 * Created by lahm on 2017/11/10.
 * 代码参考
 * http://www.wjdiankong.cn/android%E4%B8%AD%E7%9A%84apk%E7%9A%84%E5%8A%A0%E5%9B%BA%E5%8A%A0%E5%A3%B3%E5%8E%9F%E7%90%86%E8%A7%A3%E6%9E%90%E5%92%8C%E5%AE%9E%E7%8E%B0/
 * 感谢四哥
 * http://www.wjdiankong.cn/
 * <p>
 * 加壳程序工作流程：
 * 1、加密源程序APK文件为解壳数据
 * 2、计算解壳数据长度，并添加该长度到解壳DEX文件头末尾，并继续解壳数据到文件头末尾。
 * （插入数据的位置为0x70处）
 * 3、修改解壳程序DEX头中checksum、signature、file_size、header_size、string_ids_off、type_ids_off、proto_ids_off、field_ids_off、
 * method_ids_off、class_defs_off和data_off相关项。  分析map_off 数据，修改相关的数据偏移量。
 * 4、修改源程序AndroidMainfest.xml文件并覆盖解壳程序AndroidMainfest.xml文件。
 * <p>
 * 解壳DEX程序工作流程：
 * 1、从0x70处读取解壳数据长度。
 * 2、从DEX文件读取解壳数据，解密解壳数据。以文件形式保存解密数据到a.APK
 * 3、通过DexClassLoader动态加载a.APK。
 */
public class DexShellTool {

    private static String PATH_wait4DexShellSrcApk = "/Users/lahm/Desktop/force/app-a-release.apk";
    private static String PATH_unShellDexFile = "/Users/lahm/Desktop/force/ForceApkObj.dex";
    private static String PATH_OUTPUT = "/Users/lahm/Desktop/force/classes.dex";

    public static void main(String[] args) {
        try {
            File wait4DexShellSrcApk = new File(PATH_wait4DexShellSrcApk);   //待加壳的源apk
            System.out.println("apk size:" + wait4DexShellSrcApk.length());
            File unShellDexFile = new File(PATH_unShellDexFile);    //脱壳程序编译出来的dex

            //以二进制形式读出apk，并进行加密处理，用于对源Apk进行加密操作
            byte[] encryptSrcApkArray = encrypt(readFileBytes(wait4DexShellSrcApk));
            //被二进制读取并加密后的apk文件长度
            int encryptSrcApkArrayLen = encryptSrcApkArray.length;
            //以二进制形式读出脱壳dex
            byte[] unShellDexArray = readFileBytes(unShellDexFile);
            int unShellDexLen = unShellDexArray.length;
            //多出4字节是存放: 待加壳源apk的数据长度
            int totalLen = encryptSrcApkArrayLen + unShellDexLen + 4;
            //申请了新的长度
            byte[] newDex = new byte[totalLen];
            //先添加脱壳代码: 取0位置开始的unShellDexArray数据，放到0位置开始的newDex里，占用其unShellDexLen个长度
            System.arraycopy(unShellDexArray, 0, newDex, 0, unShellDexLen);//先拷贝dex内容
            //再添加已被加密后的源数据，取0位置开始的encryptSrcApkArray数据，放到unShellDexLen位置开始的newDex里，占用其encryptSrcApkArrayLen个长度
            System.arraycopy(encryptSrcApkArray, 0, newDex, unShellDexLen, encryptSrcApkArrayLen);
            //最后添加待加壳源apk的数据长度，放到newDex的最后4个字节位置上，记得把这个int类型的长度转成byte型
            System.arraycopy(intToByte(encryptSrcApkArrayLen), 0, newDex, totalLen - 4, 4);//最后4为长度
            //修改DEX file_size文件头
            fixFileSizeHeader(newDex);
            //修改DEX SHA1 (signature)文件头
            fixSHA1Header(newDex);
            //修改DEX CheckSum文件头
            fixCheckSumHeader(newDex);

            //最后的输出文件
            File file = new File(PATH_OUTPUT);
            if (!file.exists()) {
                file.createNewFile();
            }

            //数据灌注
            FileOutputStream localFileOutputStream = new FileOutputStream(PATH_OUTPUT);
            localFileOutputStream.write(newDex);
            localFileOutputStream.flush();
            localFileOutputStream.close();


        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 以二进制方式读出文件内容
     *
     * @param file
     * @return
     * @throws IOException
     */
    private static byte[] readFileBytes(File file) throws IOException {
        byte[] arrayOfByte = new byte[1024];
        ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
        FileInputStream fis = new FileInputStream(file);
        while (true) {
            int i = fis.read(arrayOfByte);
            if (i != -1) {
                localByteArrayOutputStream.write(arrayOfByte, 0, i);
            } else {
                return localByteArrayOutputStream.toByteArray();
            }
        }
    }

    /**
     * 自定义供加密 源apk数据的方法，这里只对每个字节进行异或操作
     */
    private static byte[] encrypt(byte[] src_data) {
        for (int i = 0; i < src_data.length; i++) {
            src_data[i] = (byte) (0xFF ^ src_data[i]);
        }
        return src_data;
    }

    /**
     * int 转byte[]
     * 就是一个 256 进制的算法
     * 结果高位在前，低位在后
     *
     * @param number
     * @return
     */
    public static byte[] intToByte(int number) {
        byte[] b = new byte[4];
        for (int i = 3; i >= 0; i--) {
            b[i] = (byte) (number % 256);
            number >>= 8;
        }
        return b;
    }

    /**
     * 修改dex头 file_size值
     *
     * @param dexBytes
     */
    private static void fixFileSizeHeader(byte[] dexBytes) {
        //新文件长度
        byte[] newFileSize = intToByte(dexBytes.length);
        byte[] refs = new byte[4];
        //新文件长度结果需要，低位在前，高位在后
        for (int i = 0; i < 4; i++) {
            refs[i] = newFileSize[newFileSize.length - 1 - i];
        }
        //修改第32-35位数据，也就是把脱壳程序的长度替换掉
        System.arraycopy(refs, 0, dexBytes, 32, 4);
    }

    /**
     * 修改dex头 sha1值
     * 是dex头的signature段，用sha1算法 hash 除去"magic ,checksum 和 signature "外剩余的所有文件区域
     * 用于唯一识别本文件
     *
     * @param dexBytes
     * @throws NoSuchAlgorithmException
     */
    private static void fixSHA1Header(byte[] dexBytes)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(dexBytes, 32, dexBytes.length - 32);//从32为到结束计算sha--1
        byte[] newSignature = md.digest();
        System.arraycopy(newSignature, 0, dexBytes, 12, 20);//修改sha-1值（12-31）
        //输出sha-1值，可有可无
        String hexStr = "";
        for (int i = 0; i < newSignature.length; i++) {
            hexStr += Integer.toString((newSignature[i] & 0xff) + 0x100, 16)
                    .substring(1);
        }
        System.out.println("new sha1:-- " + hexStr);
    }


    /**
     * 修改dex头，CheckSum 校验码
     * 文件校验码 ，使用alder32 算法校验文件除去"magic ，checksum "外剩余的所有文件区域
     * 用于检查文件错误
     *
     * @param dexBytes
     */
    private static void fixCheckSumHeader(byte[] dexBytes) {
        Adler32 adler = new Adler32();
        adler.update(dexBytes, 12, dexBytes.length - 12);//从12到文件末尾计算校验码
        long value = adler.getValue();
        int va = (int) value;
        byte[] newCheckSum = intToByte(va);
        //新长度结果需要，低位在前，高位在后
        byte[] recs = new byte[4];
        for (int i = 0; i < 4; i++) {
            recs[i] = newCheckSum[newCheckSum.length - 1 - i];
        }
        System.arraycopy(recs, 0, dexBytes, 8, 4);//效验码赋值（8-11）
        System.out.println("CheckSum:-- " + Long.toHexString(value));
    }
}
