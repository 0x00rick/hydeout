---
layout: post
title: "Crackme challenge 50 pts"
description: ""
category: [crackmes]
tags: [reverse engineering]
---

## Binary

Another day another write up. I'll migrate all my write ups slowly to this new blog, since I have the feeling the readibilty here is way better.


	re50: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0333e23e0d2046a0ceb6b920faebaa0b6ee45f15, stripped


So nothing crazy for this one. The binary is stripped and hence we have to do a little more work to figure out the symbol names.

[Binary download]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re50_crackme/re50" | absolute_url }})  
[Binary BinaryNinja file download]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re50_crackme/re50.bndb" | absolute_url }})  

	
---

	$ ./crackme 
	Usage : ./crackme password


It seems to be a classic crackme where the password has to be provided upon execution.


## The disassembly

The binary itself does not provide much to fiddle around with.

The main function first checks if we did provide a password upon starting the crackme.
If not it exits right away.
We already observed that during our first execution before.

![main]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re50_crackme/main.png" | absolute_url }})

If we did provide a password we directly get to the only operation routine which we need to solve.
First what was meant to be a password length check takes places to see if our input has 0x15 (21) characters. This check is broken in my binary. Maybe i fetched a broken version (check `0x8048746`).

Next up we land in a loop which does mainly 2 things:

![routine]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re50_crackme/juice.png" | absolute_url }})


### First

The binary loads the address `0x8048550` into eax and adds the current loop counter on it.
So depending on the loop iteration we end up with `0x8048551`, `0x8048552`, ... , until `0x8048565`.   
We always check the **contents** at the new address and take the LSB of it.


### Secondlly

We take a byte of our user provided input and XOR it against some hard coded stored values at `0x8049b90`.   
Afterwards we compare that result against the value of the first step above.
This happens in each round until a length of 21 characters.

## The math to do

What it comes down to in the end is:

	which_user_input XORed content_byte_at_calculated_round_address = hard_coded_round_byte_value
	

Luckily we can transform the xor math like this:

	? xor b = c equals b xor c = ?
	
Since we can read out the values for b adn c from memory we can write a simple python script to calculate the correct input:

{% highlight python %}
#!/usr/bin/env python

import operator as op

# gdb-peda$ x/25xb 0x8049b90
fixed_list = [0x34, 0xd6, 0xa8, 0xe2, 0x88, 0x77, 0xaa, 0x04,
              0x9e, 0x98, 0x33, 0x82, 0xda, 0x54, 0x8f, 0x1b,
              0x45, 0x5b, 0x37, 0xbb, 0x1d]

# gdb-peda$ x/32xb 0x8048550
xor_values = [0x55, 0x89, 0xe5, 0x83, 0xec, 0x28, 0xc7, 0x45,
              0xf0, 0xc7, 0x45, 0xf4, 0xeb, 0x20, 0xc7, 0x44,
              0x24, 0x04, 0x01, 0x8b, 0x45]
result = ''

for (x, y) in zip(fixed_list, xor_values):
    key_part = op.xor(x, y)
    result += unichr(key_part)
print(result)
{% endhighlight %}

And that's it!
Here is the solution to the problem above:

	$ python solve.py
	a_Mad_mAn_vv1tH_a_60X


Let's check for correctness:

	$ ./re50 a_Mad_mAn_vv1tH_a_60X
	Congrats!


That's it for now folks!

