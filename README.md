# Correlation-Power-Analysis
* A Python Class including codes and methods to perform statistical correlation power analysis on AES-128 Encryption
* Uses Pearson Correlation Coefficient 

## Dependencies
* numpy
* Pandas
* Matplotlib

## User Instructions and project Initialization
* make sure that the Numpy, Pandas, and Matplotlib packages are already installed on your machine.
* make sure that the CorrelationPowerAnalysis.py file, your main.py file, your power-samples CSV file, and input plaintexts CSV files are in the same directory.
* In the example project,the input plaintexts and their equivalent power samples are stored in different CSV files. 
* Simply import your desired class from CorrelationPowerAnalysis.py in your main project as well as Numpy, matplotlib, and pandas.
```py
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from CorrelationPowerAnalysis import CpaOnAES128 as CPA
```
* In the example project, we use pandas to read the input plaintexts and their equivalent power samples.
```py
plain = pd.read_csv("plain.csv").values
powerTraces = pd.read_csv("power.csv").values
```
* Create an instance from your desired class.
```py
cpaOBJ = CPA()
```
* Using .SetPlainTexts() and .SetPowerTraces() methods, we assign our measurements and plaintexts to numpy arrays in the class.
```py
cpaOBJ.SetPlainTexts(plain)
cpaOBJ.SetPowerTraces(powerTraces)
```
* Now you are able to run different methods of CPA based on what you need.

## Different CPA Methods
### cpaOBJ.CpaOnFirstKeyByte():
performs CPA on the first key byte of the AES-128 and plots the final correlation values for each key hypothesis
```py
cpaOBJ.CpaOnFirstKeyByte()
```
  
