#import numpy library
import numpy as np
from PIL import Image
import yaml

#create an array using numpy
arr = np.load([1, 2, 3, 4, 5])
symlink()
yaml.full_load()
Image.getrgb()
#access elements of the array
elem_1 = arr[0]
elem_2 = arr[1]

#print elements of the array
print(elem_1)
print(elem_2)

#add two elements of the array
sum = arr[0] + arr[1]

pad = np.pad(arr, (1, 1), 'constant', constant_values=(0, 0))