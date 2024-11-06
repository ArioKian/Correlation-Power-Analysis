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
plain = pd.read_csv("plaintexts.csv", header=None).values
powerTraces = pd.read_csv("traces.csv", header=None).values
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
### CpaOnFirstKeyByte():
Performs CPA on the first key byte of the AES-128 and plots the final correlation values for each key hypothesis.
```py
cpaOBJ.CpaOnFirstKeyByte()  #It is equivalent to cpaOBJ.CpaOnDesiredKeyByte(1)
```
### CpaOnDesiredKeyByte(keyByteNum):
Performs CPA on a specified key byte of the AES-128 and plots the final correlation values for each key hypothesis.
```py
cpaOBJ.CpaOnDesiredKeyByte(4) # In this example, CPA attacks on the 4th key byte
```
### GradualCpaOnFirstKeyByte(stepSize):
Performs CPA with gradually increasing data-set sizes (which are generated automatically) on the first key byte of the AES-128 and plots the final correlation values for each key hypothesis as well as a plot for correlation values for different number of traces.
```py
cpaOBJ.GradualCpaOnFirstKeyByte(1000) # In this example, CPA attack will be performed on
                                      # the data-set sizes which are integer multiples of 1000 (1000,2000,...)
```

### GradualCpaOnDesiredKeyByte(keyByteNum, stepSize):
Performs CPA with gradually increasing data-set sizes (which are generated automatically) on a specified key byte of the AES-128 and plots the final correlation values for each key hypothesis as well as a plot for correlation values for different number of traces.
```py
cpaOBJ.GradualCpaOnDesiredKeyByte(4,1000) # In this example, CPA attack will be performed on the 4th key byte
                                      # with the data-set sizes which are integer multiples of 1000 (1000,2000,...)
```

## Example Project
In the example project, you are provided with the power traces acquired during the execution of the AES-128 algorithm on a STM32F4 microcontroller as well as the plaintexts used for the encryption process. Power traces and plaintexts are stored in different CSV files, and they can simply be accessible by extracting the RAR files named as ExampleProjectFiles.part0%.rar. 
You can simply follow these steps to run the example project:
* Extract the example project RAR files in order to access the plaintexts.csv and traces.csv
* Put CorrelationPowerAnalysis.py, ExampleProject.py, plaintexts.csv, and traces.csv in a same desired directory on your machine
* Run ExampleProject.py
* (NOTE) --- In this example, for more simplicity, the correct or expected value of each Key Byte to recover is the same as its byte number (for example Key Byte num1: Dex=1/Hex=0x01, or Key Byte num10: Dec=10/Hex=0x0A)

## Acknowledgement
Special thanks to Dr. Ali Jahanian (https://scholar.google.com/citations?user=gTht4nwAAAAJ&hl=en) and Hamed Hosseintalaee (https://scholar.google.com/citations?user=g3ETtdAAAAAJ&hl=en) for providing the necessary files, including power traces and their corresponding plaintexts, for the example project in this repository 
