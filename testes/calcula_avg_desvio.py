



# Python3 code to demonstrate working of
# Mean deviation of Elements
# Using loop + mean() + abs()
from statistics import mean
 
# initializing list
#test_list = [2376, 2556, 2088, 1764, 828, 3348, 2592, 2232, 1836] 
         
test_list = [ 432, 444, 488, 592, 400, 456, 828,  592, 488, 468  ]

#test_list = [7, 5, 1, 2, 10, 3]
 
# Imprimindo lista original 
print("Lista original:                             " + str(test_list))
 
res = []
 
# media dos tempos
mean_val = mean(test_list)
 
for ele in test_list:
    # getting deviation
    res.append(abs(ele - mean_val))
 
# printing result
print("Desvio padrao de cada item com a media:     ", end=' ')

for i in res:
    print(f"{i:.3f}", end=' ')

print()

media_desvio = mean(res)
print(f"Media dos tempos: {mean_val:.3f}")
print(f"Media do desvio padrao: {round(media_desvio, 4)}")
