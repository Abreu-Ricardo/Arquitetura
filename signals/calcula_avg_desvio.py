



# Python3 code to demonstrate working of
# Mean deviation of Elements
# Using loop + mean() + abs()
from statistics import mean
 
# initializing list
#test_list = [ 2520, 2016, 2124, 2520, 2088, 3564, 2808,  2412] 

# send_pkt(100)
#test_list = [2318976 , 2363220 , 2382696 , 2433816 , 2527740 , 2549880 , 2472660 , 2890116 , 2519028 , 2479464 ] 

# send_pkt(500)
#test_list = [ 12761532 , 12470004 , 12030984 , 10598688 , 11303208 , 11482956 , 10590912 , 11777220 , 12636072 , 12232440]
#
## send_pkt(1000)
#test_list = [ 23662548 , 22770648 , 22212396 , 22461552 , 23890860 , 23514912 , 24385068 , 23139396 , 24895656 , 25126632]

###################################

# envia_sinal(100)
#test_list = [ 903312 , 701676 , 989280 , 749484 , 1018296 , 896220 , 909540 , 937656 , 903276 , 963684 ]
#
## envia_sinal(500)
#test_list = [ 4094064 , 4246308 , 4863132 , 4691196 , 5050008 , 4255560 , 4838256 , 4694508 , 4671360 , 4502988 ]
#
## envia_sinal(1000)
test_list = [ 7993296 , 8718624 , 8176500 , 7955748 , 9005364 , 8263692 , 8525520 , 8135532 , 8214444 , 9097020]










#test_list = [7, 5, 1, 2, 10, 3]

# Imprimindo lista original 
print("Lista original:                             " + str(test_list))
 
res = []
 
# media dos tempos
mean_val = mean(test_list)
 
for ele in test_list:
    # getting deviation
    res.append(abs(ele - mean_val))

print(f"Media dos valores:                          {mean_val}")

# printing result
print("Desvio padrao de cada item com a media:     ", end=' ')

for i in res:
    print(f"{i:.3f}", end=' ')

print()

media_desvio = mean(res)
print(f"Media dos tempos: {mean_val:.3f}")
print(f"Media do desvio padrao: {round(media_desvio, 4)}")
