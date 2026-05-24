
## Prover
We have from the spec that:
$$
u = \sum_{i = 0}^{N-1} PRG(sd_i)
$$
$$
v = \sum_{i = 0}^{N-1} i \cdot PRG(sd_i)
$$
An example for $N = 4$ and thereby $d = \log_2(N) = 2$
Firstly
$$
r[0][0] = PRG(sd_0)
$$
$$
r[0][1] = PRG(sd_1)
$$
$$
r[0][2] = PRG(sd_2)
$$
$$
r[0][3] = PRG(sd_3)
$$
At the same time for each $i$
$$
0 = [00]
$$
$$
1 = [01]
$$
$$
2 = [10]
$$
$$
3 = [11]
$$
The value of $v[j]$, we want it so that that for the if it is 1 in the $j$ spot of $i$, then it is included in the sum thereby:
$$
v[0] = r[0][1] \oplus r[0][3]
$$
$$
v[1] = r[0][2] \oplus r[0][3]
$$
This is realized in the loop
```
let zero_v = [0; ell_hat_bytes];  
// v[j] will hold the j-th component of the field element v in F_{2^d},  
// i.e. v[j] = XOR of PRG(sd_i) for all i where bit j of i is 1  
let mut v: [[u8; ell_hat_bytes]; d] = [zero_v; d];  
for j in 0..d {  
    // at level j there are N / 2^{j+1} pairs of nodes to process  
    let i_range : usize = sds.len() >> (j + 1); // prev: sds.len() / 2_i32.pow(j + 1)  
    for i in 0..i_range {  
        if let (Some(r1), Some(r2)) = (r[j][2*i], r[j][2*i+1]) {  
        
			v[j] = xor_arrays(&v[j], &r2);  
            
            let new_r: [u8; ell_hat_bytes] = xor_arrays(&r1, &r2);  
            r[j+1][i] = Some(new_r);  
        }  
    }  
}
```


$j$ runs from $0$ to $1$
At the same time we have $i\_range$, Where for each iteration $N / 2^{j+1}$, so for the first:
$$
i\_range = \frac{4}{2^1} = 2
$$
The loop runs in the first iteration from and to 0, 1
first iteration $i = 0$
```
r_1 = r[0][0]
r_2 = r[0][1]
v[0] = v[0] xor r_2 = v[0] xor r[0][1] = r[0][1]
r[1][0] = r_1 xor r_2 = r[0][0] xor r[0][1]
```
second iteration $i = 1$
```
r_1 = r[0][2]
r_2 = r[0][3]
v[0] = v[0] xor r_2 = r[0][1] xor r[0][3]
r[1][1] = r_1 xor r_2 = r[0][2] xor r[0][3]
```

for $j = 1$
here we have that
$$
i\_range = \frac{4}{2^2} = 1
$$
thereby it only runs for $i = 0$
```
r_1 = r[1][0]
r_2 = r[1][1]
v[1] = v[1] xor r_2 = r[1][1] = r[0][2] xor r[0][3]
r[2][0] = r_1 xor r_2 = r[1][0] xor r[1][1] = r[0][0] xor r[0][1] xor r[0][2] xor r[0][3]
```

So here we have that
$$
v[0] = r[0][1] \oplus r[0][3]
$$
$$
v[1] = r[0][2] \oplus r[0][3]
$$
The last thing we do is that we set $u = r[d][0]$
```
u = r[2][0] = r_1 xor r_2 = r[1][0] xor r[1][1] = r[0][0] xor r[0][1] xor r[0][2] xor r[0][3]
```
Which is the same as:
$$
u = \sum_{i = 0}^{N-1} PRG(sd_i)
$$

## Verfier
We also have that:
$$
q = \sum_{i = 0}^{N-1} (\Delta -i) \cdot r_i
$$
This is what the verifier wants when he calls convert to vole through the vole reconstruct function
Firstly we can expand the above
$$
q = \sum_{i = 0}^{N-1} (\Delta -i) \cdot r_i = \sum_{i = 0}^{N-1} \Delta \cdot r_i - \sum_{i = 0}^{N-1} i \cdot r_i = \Delta \cdot\sum_{i = 0}^{N-1}  r_i - \sum_{i = 0}^{N-1} i \cdot r_i = \Delta \cdot u - v
$$
So thats the vole correlation we want
The problem is that the verifier doesnt know the seed for $\Delta$
But the cool thing is that when $i = \Delta$, then it holds that $\Delta - i = 0$ and then $(\Delta - i) \cdot r_i = 0$, for that specific $i$, i.e. the hidden seed won't contribute anything to the sum.
An important thing that the verifier does is that it permutes the seeds, it makes a permutation where:
```
sd[j] = sd[j xor Delta]
```
This is done for each $j \in \{N-1\}$

This gives us such that:
```
sd[0] = sd[Delta]
```
I.e. the one we don't know so this value is set to zero
So now if we run the same example we have that, where lets say $\Delta = 3$:
$$
r[0][0] = PRG(sd_{0 \oplus 3}) = PRG(sd_3) = PRG(0)
$$
$$
r[0][1] = PRG(sd_{1 \oplus 3}) = PRG(sd_2)
$$
$$
r[0][2] = PRG(sd_{2 \oplus 3}) = PRG(sd_1)
$$
$$
r[0][3] = PRG(sd_{3 \oplus 3}) = PRG(sd_0)
$$

Then by running the exact same iteration as for $v[j]$, we get that:
$$
q[0] = r[0][1] \oplus r[0][3]
$$
$$
q[1] = r[0][2] \oplus r[0][3]
$$
More explictely we get that:
$$
q[0] = PRG(sd_2) \oplus PRG(sd_0)
$$
$$
q[1] = PRG(sd_1) \oplus PRG(sd_0)
$$
And before we got that:
$$
v[0] = r[0][1] \oplus r[0][3] = PRG(sd_1) \oplus PRG(sd_3)
$$
$$
v[1] = r[0][2] \oplus r[0][3] = PRG(sd_2) \oplus PRG(sd_3)
$$
$$
u = r[0][0] \oplus r[0][1] \oplus r[0][2] \oplus r[0][3] = PRG(sd_0) \oplus PRG(sd_1) \oplus PRG(sd_2) \oplus PRG(sd_3)
$$

Then it so that the value of q is:
$$
q[j] = v[j] \oplus \delta_j \cdot u
$$
Where $\delta_j \in \{0,1\}$, based on the bits of $\Delta$, but since $\Delta = 3$, then both values are 1, so:
$$
q[0] = v[0] \oplus u
$$
That means all RPG values not in $v[0]$, otherwise it would be exactly the values in $v[0]$, so here we have that:
$$
v[0] \oplus u = PRG(sd_3) \oplus PRG(sd_1) \oplus PRG(sd_0) \oplus PRG(sd_1) \oplus PRG(sd_2) \oplus PRG(sd_3)
$$
$$
v[1] \oplus u = PRG(sd_2) \oplus PRG(sd_3) \oplus PRG(sd_0) \oplus PRG(sd_1) \oplus PRG(sd_2) \oplus PRG(sd_3)
$$
Where we then get that:
$$
v[0] \oplus u = PRG(sd_2) \oplus PRG(sd_0)
$$
$$
v[1] \oplus u = PRG(sd_1) \oplus PRG(sd_3)
$$
Which is exactly q