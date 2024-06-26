## 推广RSA共模攻击的秘密共享方案
我不知道有没有前人提出过，我感觉这么简单的东西肯定有人提出过，但我没搜到相关的论文

$$
p,q,n=p\times q,\phi(n)=(p-1)(q-1),m,
$$

取小于n的pq以外的素数t1、t2、t3，计算：

$$
\begin{gather}
e_1=t_1\times t_2 \\
e_2=t_2\times t_3 \\
e_3=t_3\times t_1 \\
d_1=e_1^{-1}mod\ \phi(n) \\
d_2=e_2^{-1}mod\ \phi(n) \\
d_3=e_3^{-1}mod\ \phi(n) \\
\end{gather}
$$

已知

$$
\begin{gather}
c_1=m^{e_1} mod\ n\\
c_2=m^{e_2} mod\ n\\
c_3=m^{e_3} mod\ n\\
\end{gather}
$$

则存在

$$
\begin{gather}
e_1 u_1+e_2 u_2=t_2\\
t_2 u_3+e_3 u_4=1\\
(e_1 u_1+e_2 u_2)u_3+e_3 u_4=1\\
e_1 u_1 u_3+e_2 u_2 u_3+e_3 u_4=1\\
e_1 s_1+e_2 s_2+e_3 s_3=1
\end{gather}
$$

上面的u1,u2,u3,u4可以用扩展欧几里得算法得到，s1,s2,s3可以由u1,u2,u3,u4计算得到，有s1,s2,s3就可以算明文：

$$
\begin{gather}
m=m^{(e_1 s_1 + e_2 s_2 + e_3 s_3)}\\
=m^{e_1 s_1}m^{e_2 s_2}m^{e_3 s_3}\\
=c_1^{s_1}c_2^{s_2}c_3^{s_3}
\end{gather}
$$

也就是说知道三个密文和公钥就能解出明文

密文数和密钥数是相同的，每一对作为一个属性

现在的问题是如何构造属性(e和c，c是由e计算的，所以下面只讨论e)

可以添加公共元素t使得任意两个e之间最大公约数不为1

所以就可以遍历所有不应该允许的e的组合，为其添加相同的t

例如，对于5个e，希望有三个e就能解出，则意味着所有两个的组合不能解出

所以遍历 $C^2_5$ 中所有组合，添加相同的因子t，结果如下：

$$
\begin{gather}
e_1=t_{1} t_{2} t_{3} t_{4}\\
e_2=t_{1} t_{5} t_{6} t_{7}\\
e_3=t_{2} t_{5} t_{8} t_{9}\\
e_4=t_{3} t_{6} t_{8} t_{10}\\
e_5=t_{4} t_{7} t_{9} t_{10}\\
\end{gather}
$$

可以发现任意2个e最大公约数都不是1，而任意3个都是1

这是简单的访问规则，也可以定义一堆互不为子集的e的集合，只有收集到某个集合的真超集的时候才能解出
