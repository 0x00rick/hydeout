---
layout: post
title: "Crackme challenge 200 pts"
description: ""
category: [crackmes]
tags: [reverse engineering]
---

Another week, another binary :).  

	➜  re_200 git:(master) ✗ file r200
	r200: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=22e68980e521b43c90688ed0693df78150b10211, stripped

This time around we have another x64 stripped binary to work with.  
Let's first try to see what input might be expected again!  

	➜  re_200 git:(master) ✗ ./r200
	Enter the password: asdfgh
	Incorrect password!

So the only data we can gather from that is that our password was wrong.
No length requirements or hints at all.  
That should not worry us much, since by now we're okay with diving into the assembly and take a look at what we have in front of us!  


[Binary download]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re200_crackme/re200" | absolute_url }})  
[annotated Binary BinaryNinja file]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re200_crackme/re201.bndb" | absolute_url }})  



## Main

![main]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re200_crackme/main.png" | absolute_url }})  

Here we can see the main function of the binary.  
At first we have the usual initialization routine before entering a branching block right away.  
There we compare a variable to `0xa (10)`.  
That variable is a typical loop counter.  
Since it was initialized with 0 before the `jle` obviously succeeds and we're entering the code block to the left (`0x4008ad` to `0x4008f0`) in the picture above.  
In here a couple of interesting things happen already, which we need later on to fully understand what was going on in the binary.  

> Note: Keep in mind we're reading x64 assembly. So recall the x64 ABI!

	[...]
	|       |   ; JMP XREF from 0x004008f8 (main)
	|      .--> 0x004008ad      bf10000000     mov edi, 0x10               		; 16
	|      :|   0x004008b2      e889fdffff     call sym.imp.malloc         		;  void *malloc(size_t size)
	|      :|   0x004008b7      488945e8       mov qword [ptr_to_allocated_mem], rax
	|      :|   0x004008bb      488b45e8       mov rax, qword [ptr_to_allocated_mem]; load ptr to allocated mem in rax
	|      :|   0x004008bf      8b55e4         mov edx, dword [loopCounter1]	; move loop counter in edx
	|      :|   0x004008c2      8910           mov dword [rax], edx			; store loop counter at allocated mem
	|      :|   0x004008c4      488b45e8       mov rax, qword [ptr_to_allocated_mem]; load ptr to allocated mem in rax
	|      :|   0x004008c8      8b00           mov eax, dword [rax]			; move loop counter in eax
	|      :|   0x004008ca      83c06d         add eax, 0x6d               		; add 'm' on loop counter
	|      :|   0x004008cd      89c2           mov edx, eax				; move result from eax in edx
	|      :|   0x004008cf      488b45e8       mov rax, qword [ptr_to_allocated_mem]; load ptr to allocated mem in rax
	|      :|   0x004008d3      885004         mov byte [rax + 4], dl		; store value 4 bytes behind loop counter
	|      :|   0x004008d6      488b15a30720.  mov rdx, qword [0x00601080] 		; load previous mem location where stuff got stored
	|      :|   0x004008dd      488b45e8       mov rax, qword [ptr_to_allocated_mem]; load ptr to current allocated mem in rax
	|      :|   0x004008e1      48895008       mov qword [rax + 8], rdx		; store prev mem location 8 bytes after current values in mem
	|      :|   0x004008e5      488b45e8       mov rax, qword [ptr_to_allocated_mem]
	|      :|   0x004008e9      488905900720.  mov qword [0x00601080], rax 		; store current mem location at that addr
	|      :|   0x004008f0      8345e401       add dword [loopCounter1], 1		; increment loop counter
	|      :|   ; JMP XREF from 0x004008ab (main)
	|      :`-> 0x004008f4      837de40a       cmp dword [loopCounter1], 0xa  	; cmp loop counter to 0xa
	|      `==< 0x004008f8      7eb3           jle 0x4008ad				; if <=0xa enter loop
	[...]

Right of the bat a `malloc(16)` call is happening.


	The malloc() function allocates size bytes and returns a pointer to the
	allocated memory.  The memory is not initialized.  If size is  0,  then
	malloc()  returns either NULL, or a unique pointer value that can later
	be successfully passed to free().

What this code block basically does is the following. It allocates 16 bytes worth of memory via `malloc`.  
Then the current loop counter is written at the address where our freshly allocated memory points to.  
Next up an addition takes places, where the current loop counter is added on top of some value `0x6d`.  
The result is placed 4 bytes after the written loop counter.  
So memory looks like this now:

	0x602260:	0x00000001	0x0000006e
	<memory>:	<loop_cntr>	<value>

After successfully doing so the loop counter is incremented. This is done 10 times.  
So memory after this code block looks like this:

	0x602240:	0x00000000	0x00000000	0x00000000	0x00000000
	0x602250:	0x00000000	0x00000000	0x00000021	0x00000000
	0x602260:	0x00000001	0x0000006e	0x00000000	0x00000000
	0x602270:	0x00000000	0x00000000	0x00000021	0x00000000
	0x602280:	0x00000002	0x0000006f	0x00602260	0x00000000
	0x602290:	0x00000000	0x00000000	0x00000021	0x00000000
	0x6022a0:	0x00000003	0x00000070	0x00602280	0x00000000
	0x6022b0:	0x00000000	0x00000000	0x00000021	0x00000000
	0x6022c0:	0x00000004	0x00000071	0x006022a0	0x00000000
	0x6022d0:	0x00000000	0x00000000	0x00000021	0x00000000
	0x6022e0:	0x00000005	0x00000072	0x006022c0	0x00000000
	0x6022f0:	0x00000000	0x00000000	0x00000021	0x00000000
	0x602300:	0x00000006	0x00000073	0x006022e0	0x00000000
	0x602310:	0x00000000	0x00000000	0x00000021	0x00000000
	0x602320:	0x00000007	0x00000074	0x00602300	0x00000000
	0x602330:	0x00000000	0x00000000	0x00000021	0x00000000
	0x602340:	0x00000008	0x00000075	0x00602320	0x00000000
	0x602350:	0x00000000	0x00000000	0x00000021	0x00000000
	0x602360:	0x00000009	0x00000076	0x00602340	0x00000000
	0x602370:	0x00000000	0x00000000	0x00000021	0x00000000
	0x602380:	0x0000000a	0x00000077	0x00602360	0x00000000


When inspecting these values we can easily identify a data structure!  
A linked list, where the next allocated chunk of memory always points to the previous one too!  

	    +----------+      +----------+      +----------+      +-----------+
	    |          |      |          |      |          |      |           |
	    |          |      |          |      |          |      |           |
    ... +-----> cur addr +------+  index   +------+  value   +------+ prev addr +----> ...
	    |          |      |          |      |          |      |           |
	    |          |      |          |      |          |      |           |
	    +----------+      +----------+      +----------+      +-----------+



When this loop iterated 10 times the `jle` instruction @ `0x4008f8` fails and control flow is redirected.  
The next code block is not as interesting. Here user input is prompted via `fgets`, after `printf` outputs some text to the command line.  
Afterwards a new function is called with the user input as the argument.  
Before I jump right into that one, let's take a look at the assembly after the function exits again!  


	[...]
	|       |   0x00400926      488d45f0       lea rax, [user_input]
	|       |   0x0040092a      4889c7         mov rdi, rax			   ; push user input in rdi for function argument
	|       |   0x0040092d      e81bfeffff     call fcn.0040074d		   ; call password checking function
	|       |   0x00400932      85c0           test eax, eax		   ; function needs to return 0 to pass this test
	|      ,==< 0x00400934      7511           jne 0x400947			   ; if test eax,eax fails jump to bad ending!!!
	|      ||   0x00400936      bf240a4000     mov edi, str.Nice               ; 0x400a24 ; "Nice!"
	|      ||   0x0040093b      e8a0fcffff     call sym.imp.puts               ; int puts(const char *s)
	|      ||   0x00400940      b800000000     mov eax, 0
	|     ,===< 0x00400945      eb16           jmp 0x40095d
	|     |||   ; JMP XREF from 0x00400934 (main)
	|     |`--> 0x00400947      bf2a0a4000     mov edi, str.Incorrect_password ; 0x400a2a ; "Incorrect password!" ; const char * s
	|     | |   0x0040094c      e88ffcffff     call sym.imp.puts           	   ; int puts(const char *s)
	|     | |   0x00400951      b801000000     mov eax, 1
	|     |,==< 0x00400956      eb05           jmp 0x40095d
	|     |||   ; JMP XREF from 0x00400924 (main)
	|     ||`-> 0x00400958      b800000000     mov eax, 0
	|     ||    ; JMP XREF from 0x00400956 (main)
	|     ||    ; JMP XREF from 0x00400945 (main)
	|     ``--> 0x0040095d      488b4df8       mov rcx, qword [local_8h]
	|           0x00400961      6448330c2528.  xor rcx, qword fs:[0x28]
	|       ,=< 0x0040096a      7405           je 0x400971
	|       |   0x0040096c      e87ffcffff     call sym.imp.__stack_chk_fail   ; void __stack_chk_fail(void)
	|       |   ; JMP XREF from 0x0040096a (main)
	|       `-> 0x00400971      c9             leave
	\           0x00400972      c3             ret

When the called function exits a `test 	eax,eax` is called immediately. It's directly followed by `jne`, which if true jumps to the bad ending.  
So we already know we need to ensure that the function exits with `eax` holding the value 0!  

## Password check routine

![pwcheck]({{ "https://github.com/0x00rick/0x00rick.github.com/raw/master/assets/re200_crackme/checkpw.png" | absolute_url }})

This function can be broken down into smaller pieces once again.  

	[...]
	|           0x0040074d      55             push rbp
	|           0x0040074e      4889e5         mov rbp, rsp
	|           0x00400751      48897da8       mov qword [local_58h], rdi
	|           0x00400755      48c745b80000.  mov qword [local_48h], 0
	|           0x0040075d      48c745c00000.  mov qword [local_40h], 0
	|           0x00400765      48c745c80000.  mov qword [local_38h], 0
	|           0x0040076d      48c745d00000.  mov qword [local_30h], 0
	|           0x00400775      c745b0000000.  mov dword [local_50h], 0
	|           0x0040077c      c745e0050000.  mov dword [local_20h], 5
	|           0x00400783      c745e4020000.  mov dword [local_1ch], 2
	|           0x0040078a      c745e8070000.  mov dword [local_18h], 7
	|           0x00400791      c745ec020000.  mov dword [local_14h], 2
	|           0x00400798      c745f0050000.  mov dword [local_10h], 5
	|           0x0040079f      c745f4060000.  mov dword [local_ch], 6
	|           0x004007a6      c745b0000000.  mov dword [local_50h], 0
	|       ,=< 0x004007ad      eb5e           jmp 0x40080d
 	[...]

The function prologue initializes some values at specific addresses.  
This does not look particular exciting for now, so let's skip right ahead!  

	[...]
	|   ; JMP XREF from 0x00400811 (fcn.0040074d)
	|      .--> 0x004007af      488b05ca0820.  mov rax, qword [0x00601080] 			; [0x601080:8]=0
	|      :|   0x004007b6      488945b8       mov qword [ptr_to_some_allocated_value], rax
	|      :|   0x004007ba      c745b4000000.  mov dword [cmp_true_value], 0
	|     ,===< 0x004007c1      eb33           jmp 0x4007f6
	|     |:|   ; JMP XREF from 0x004007fb (fcn.0040074d)
	|    .----> 0x004007c3      488b45b8       mov rax, qword [ptr_to_some_allocated_value]
	|    :|:|   0x004007c7      0fb65004       movzx edx, byte [rax + 4]   			; [0x4:1]=255 ; 4
	|    :|:|   0x004007cb      8b45b0         mov eax, dword [loopCounter2]
	|    :|:|   0x004007ce      4863c8         movsxd rcx, eax
	|    :|:|   0x004007d1      488b45a8       mov rax, qword [ptr_to_user_input]
	|    :|:|   0x004007d5      4801c8         add rax, rcx                			; '&'
	|    :|:|   0x004007d8      0fb600         movzx eax, byte [rax]
	|    :|:|   0x004007db      38c2           cmp dl, al
	|   ,=====< 0x004007dd      750b           jne 0x4007ea
	|   |:|:|   0x004007df      488b45b8       mov rax, qword [ptr_to_some_allocated_value]
	|   |:|:|   0x004007e3      8b00           mov eax, dword [rax]
	|   |:|:|   0x004007e5      8945b4         mov dword [cmp_true_value], eax
	|  ,======< 0x004007e8      eb13           jmp 0x4007fd
	|  ||:|:|   ; JMP XREF from 0x004007dd (fcn.0040074d)
	|  |`-----> 0x004007ea      488b45b8       mov rax, qword [ptr_to_some_allocated_value]
	|  | :|:|   0x004007ee      488b4008       mov rax, qword [rax + 8]    			; [0x8:8]=-1 ; 8
	|  | :|:|   0x004007f2      488945b8       mov qword [ptr_to_some_allocated_value], rax
	|  | :|:|   ; JMP XREF from 0x004007c1 (fcn.0040074d)
	|  | :`---> 0x004007f6      48837db800     cmp qword [ptr_to_some_allocated_value], 0
	|  | `====< 0x004007fb      75c6           jne 0x4007c3
	|  |   :|   ; JMP XREF from 0x004007e8 (fcn.0040074d)
	|  `------> 0x004007fd      8b45b0         mov eax, dword [loopCounter2]
	|      :|   0x00400800      4898           cdqe
	|      :|   0x00400802      8b55b4         mov edx, dword [cmp_true_value]
	|      :|   0x00400805      895485c0       mov dword [rbp + rax*4 - 0x40], edx
	|      :|   0x00400809      8345b001       add dword [loopCounter2], 1
	|      :|   ; JMP XREF from 0x004007ad (fcn.0040074d)
	|      :`-> 0x0040080d      837db005       cmp dword [loopCounter2], 5    		; aeim.fd ; [0x5:4]=-1
	|      `==< 0x00400811      7e9c           jle 0x4007af
	[...]


The radare2 output above might look confusing at first, but let me try to make it more approachable.  
At first some allocated value is loaded and another register is initialized with 0 in `0x004007af` to `0x004007ba`.  
Then control flow is jumping to `0x004007f6`, where the prior loaded value is checked against 0 and if that is not the case the control flow resumes normally without a major jump to `0x004007c3`.  
This is the case when running the binary normally, since we do not influence the loaded value that is checked!  
So let's focus on the biggest and most interesting chunk of assembly here:  

	[...]
	.----> 0x004007c3      488b45b8       mov rax, qword [ptr_to_some_allocated_value]
	|    :|:|   0x004007c7      0fb65004       movzx edx, byte [rax + 4]   			; [0x4:1]=255 ; 4
	|    :|:|   0x004007cb      8b45b0         mov eax, dword [loopCounter2]
	|    :|:|   0x004007ce      4863c8         movsxd rcx, eax				; move loop counter into rcx
	|    :|:|   0x004007d1      488b45a8       mov rax, qword [ptr_to_user_input]		; move ptr to user input in rax
	|    :|:|   0x004007d5      4801c8         add rax, rcx                			; get ptr to current user input
	|    :|:|   0x004007d8      0fb600         movzx eax, byte [rax]			; load current usr input byte in eax
	|    :|:|   0x004007db      38c2           cmp dl, al					; cmp static value to user input
	|   ,=====< 0x004007dd      750b           jne 0x4007ea
	|   |:|:|   0x004007df      488b45b8       mov rax, qword [ptr_to_some_allocated_value]	; cmp succeeded if here
	|   |:|:|   0x004007e3      8b00           mov eax, dword [rax]				; load usr input byte which passed the cmp
	|   |:|:|   0x004007e5      8945b4         mov dword [cmp_true_value], eax		; set it as "cmp_true_value"
	|  ,======< 0x004007e8      eb13           jmp 0x4007fd
	|  ||:|:|   ; JMP XREF from 0x004007dd (fcn.0040074d)
	|  |`-----> 0x004007ea      488b45b8       mov rax, qword [ptr_to_some_allocated_value]	; cmp failed if here & load ptr to static value again
	|  | :|:|   0x004007ee      488b4008       mov rax, qword [rax + 8]   			; add 8 bytes to said ptr to 'load' another static value
	|  | :|:|   0x004007f2      488945b8       mov qword [ptr_to_some_allocated_value], rax ; set it as the new static value
	[...]

This part is quite straightforward. In the end what happens here is that some static/fixed value is loaded into memory and is compared against one byte from the user input, which depends on the loop counter.  
Depending on the comparison of the user provided byte and the static byte @`0x4007db` a branching happens.  

* If the comparison fails, control flow is redirected to `0x4007ea`, where ultimatiely a new static value is set, by adding 8 to the pointer to the prior static value that is compared against.

* If the comparison suceeded the user provided password byte that passed the comparison is loaded into `eax` and set in `cmp_true_value` @`0x4007df`.

-----

	[...]
	|  |   :|   ; JMP XREF from 0x004007e8 (fcn.0040074d)
	|  `------> 0x004007fd      8b45b0         mov eax, dword [loopCounter2]	; load loop counter in eax
	|      :|   0x00400800      4898           cdqe
	|      :|   0x00400802      8b55b4         mov edx, dword [cmp_true_value]	; load cmp_true_value, 0 if prior branching failed
	|      :|   0x00400805      895485c0       mov dword [rbp + rax*4 - 0x40], edx	; write to memory
	|      :|   0x00400809      8345b001       add dword [loopCounter2], 1		; increment loop counter
	[...]

When the comparison at @`0x4007df` succeeded we enter this block too, where the set `cmp_true_value` is written at a memory location, which is dependend on the current loop counter!  
Afterwards the loop counter is incremented and the whole looping structure is redone.  


#### Summary
To summarize this in a few words this whole block of code from `0x40080d` to `0x400809` we just worked through only tries compare some user input to some fixed value.  
If the current user input does not match the fixed byte the inner loop is redone with the next user input byte.   
Either until there is a match, or a check @`0x4007f6` fails and the loop counter is incremented as a result.  
Followed by entering the outer loop once again, but this time with the next byte from the user input.  

#### So what are these bytes that the user input is compared against?

That's easy!  
Remember the allocation in the `main()` method with the linked list, where first some *index* followed by a *value* was written to memory?  
Exactly against these 10 allocated *values* is compared against!  


#### What's the purpose?
This code basically checks if the user provided input matches the alphabet set by the binary, which are the values allocated in the `main()` function.  
If you look closer to the allocated values you'll notice they range from '0x6e' to '0x77', which in ASCII representation is the lettern 'n' to 'w'!  



--------

But that's not all! If you look at the provided BinaryNinja screenshot above you'll see we only covered the 'left' part of the assembly graph.  
So what happens after the loop @`0x400811` is evaluating to false?      
Let's take a look!  


	[...]
		|		   0x00400813      c745b0000000.  mov dword [loopCounter2], 0	; init loop counter to 0
		|       ,=< 0x0040081a      eb21           jmp 0x40083d
		|       |   ; JMP XREF from 0x00400841 (fcn.0040074d)
		|      .--> 0x0040081c      8b45b0         mov eax, dword [loopCounter2]	; set eax = loop counter contents
		|      :|   0x0040081f      4898           cdqe
		|      :|   0x00400821      8b5485c0       mov edx, dword [rbp + rax*4 - 0x40]	; load some value in edx [userbyte_index]
		|      :|   0x00400825      8b45b0         mov eax, dword [loopCounter2]	; set eax = loop counter contents
		|      :|   0x00400828      4898           cdqe
		|      :|   0x0040082a      8b4485e0       mov eax, dword [rbp + rax*4 - 0x20]	; load some other value into eax [passwordbyte_index]
		|      :|   0x0040082e      39c2           cmp edx, eax				; compares both
		|     ,===< 0x00400830      7407           je 0x400839
		|     |:|   0x00400832      b801000000     mov eax, 1				; if not equal set eax = 1 and return to main
		|    ,====< 0x00400837      eb0f           jmp 0x400848
		|    ||:|   ; JMP XREF from 0x00400830 (fcn.0040074d)
		|    |`---> 0x00400839      8345b001       add dword [loopCounter2], 1		; otherwise increment loop counter
		|    | :|   ; JMP XREF from 0x0040081a (fcn.0040074d)
		|    | :`-> 0x0040083d      837db005       cmp dword [loopCounter2], 5    	; check if loop counter <=5
		|    | `==< 0x00400841      7ed9           jle 0x40081c				; if yes take jump
		|    |      0x00400843      b800000000     mov eax, 0				; if loop passed 5 times set eax = 0 and return to main
		|    |      ; JMP XREF from 0x00400837 (fcn.0040074d)
		|    `----> 0x00400848      5d             pop rbp
		\           0x00400849      c3             ret
	[...]


This last part is just as important as the previous code in this function.  
Since here the outcome of the `eax` register is determined upon returning to `main()`.  
And we already found out that `eax` has to be 0!  
So what this code block does is, it loops at most 5 times upon successful comparison of two values, which depend on the loop counter!  
If all 5 iterations where successful `eax` is set to 0 and we return to main.  
That's exactly what we want.  

#### But what are the compared values this time around?

In the end the value @`0x00400821` the index of the user provided byte is loaded.  
@`0x0040082a` the index of a static value is loaded.  

The first two loops which where done beforehand made sure the entered value is part of the accepted alphabet: [n,o,p,q,r,s,t,u,v,w].  
Each of these letters got assigned an index value way back in the main function, which back then was just the value of a loop counter!  
This loop iterates over the user input and checks the indizes of each byte against a static value again.  
Since this is done 6 times we just got ourself the password length too!  
Anyway this loop does not make sure the user provided input is part of a valid alphabet, but instead makes sure the accepted characters are entered in the right ordering!  

The mapping looks as follows:

	<index> -> <value>
	1 	  -> 0x6e (n)
	2 	  -> 0x6f (o)
	3 	  -> 0x70 (p)
	4 	  -> 0x71 (q)
	5 	  -> 0x72 (r)
	6 	  -> 0x73 (s)
	7 	  -> 0x74 (t)
	8 	  -> 0x75 (u)
	9 	  -> 0x76 (v)
	a 	  -> 0x77 (w)


This mapping in which order the indizes are called to check for the password must have been saved somewhere right?  
Recall the variable initialization at the top of this function, which we skipped in the beginning?  
Exactly that is the correct ordering!  

	[...]
	|           0x0040077c      c745e0050000.  mov dword [local_20h], 5
	|           0x00400783      c745e4020000.  mov dword [local_1ch], 2
	|           0x0040078a      c745e8070000.  mov dword [local_18h], 7
	|           0x00400791      c745ec020000.  mov dword [local_14h], 2
	|           0x00400798      c745f0050000.  mov dword [local_10h], 5
	|           0x0040079f      c745f4060000.  mov dword [local_ch], 6
	[...]

If you take these values and read them as indizes then you get the password: `rotors`!

	➜  re_200 git:(master) ✗ ./r200
	Enter the password: rotors
	Nice!
