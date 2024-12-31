



# Python3 code to demonstrate working of
# Mean deviation of Elements
# Using loop + mean() + abs()
from statistics import mean
 
# initializing list
test_list = [ 2520, 2016, 2124, 2520, 2088, 3564, 2808,  2412] 
         

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
