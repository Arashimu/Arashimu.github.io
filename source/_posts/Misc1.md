---
title: Misc1
date: 2022-05-17 16:37:50
tags:
---

## 工具

### 16 进制编辑器

- sublime Hexviewer 插件
- 010editor

### 和文件分离合并有关的命令

- binwalk
  ```shell
  binwalk filename #查看文件里面的内容
  binwalk -e filename #分离文件
  ```
- `dd`命令
  ```shell
  dd if=filename1 of=filename2 bs=blokc_size count=num
  #读入文件为filename1，输出文件为filename2，读取前count个块，每个块的大小为bs
  dd if=filename1 of=filename2 bs=blokc_size count=num skip=skip_num
  #读入文件为filename1，输出文件为filename2，每个块的大小为bs，在前count块中，跳过前skip个块，输出后count-skip个块
  ```
- Linux 下：`cat`
  ```shell
  cat file1 file2 file3 > file
  #把文件1,2,3合并后输出为文件file
  ```
- Windows 下：`copy/B`
  ```shell
  copy/B file1+file2+file3 file
  #把文件1,2,3合并后输出到file
  ```
- `md5sum`
  ```shell
  md5sum filename
  #计算文件的md5值，验证文件完整性
  ```

## 常见文件的文件头

```txt
JPEG (jpg)，                        　文件头：FFD8FF　　　　　　　　　　　　　　
PNG (png)，                       　  文件头：89504E47  文件尾：0000000049454E44AE426082
GIF (gif)，                           文件头：47494638
ZIP Archive (zip)，                   文件头：504B0304  文件尾：00000000
TIFF (tif)，                          文件头：49492A00
Windows Bitmap (bmp)，      　        文件头：424D
CAD (dwg)，                        　 文件头：41433130
Adobe Photoshop (psd)，               文件头：38425053
Rich Text Format (rtf)，              文件头：7B5C727466
XML (xml)，                           文件头：3C3F786D6C
HTML (html)，                         文件头：68746D6C3E
Email [thorough only] (eml)，         文件头：44656C69766572792D646174653A
Outlook Express (dbx)，               文件头：CFAD12FEC5FD746F
Outlook (pst)，                       文件头：2142444E
MS Word/Excel (xls.or.doc)，          文件头：D0CF11E0
MS Access (mdb)，                     文件头：5374616E64617264204A
WordPerfect (wpd)，                   文件头：FF575043
Adobe Acrobat (pdf)，                 文件头：255044462D312E
Quicken (qdf)，                       文件头：AC9EBD8F
Windows Password (pwl)，              文件头：E3828596
RAR Archive (rar)，                   文件头：52617221
Wave (wav)，                          文件头：57415645
AVI (avi)，                           文件头：41564920
Real Audio (ram)，                    文件头：2E7261FD
Real Media (rm)，                     文件头：2E524D46
MPEG (mpg)，                          文件头：000001BA
MPEG (mpg)，                          文件头：000001B3
Quicktime (mov)，                     文件头：6D6F6F76
Windows Media (asf)，                 文件头：3026B2758E66CF11
MIDI (mid)，                          文件头：4D546864
```

## 图片隐写常见方法

1. 细微的颜色差别
2. GIF 图多帧隐藏
   - 颜色通道隐藏
   - 不同帧图信息隐藏
   - 不同帧对比隐写
3. Exif 信息隐藏
4. 图片修复
   - 图片头修复
   - 图片尾修复
   - CRC 校验修复
   - 长、宽、高修复
5. 最低有效位 LSB 隐写
6. 图片加密
   - Stegdetect
   - outguess
   - Jphide
   - F5
