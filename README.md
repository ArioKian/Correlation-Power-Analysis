# Correlation-Power-Analysis
* A Python Class including codes and methods to perform statistical correlation power analysis on AES-128 Encryption
* Uses Pearson Correlation Coefficient 

## Dependencies
* numpy
* Pandas
* Matplotlib

## User Instructions
* make sure that the CorrelationPowerAnalysis.py file, your main.py file, your power-samples CSV file, and input plaintexts CSV files are in the same directory
* In the example project input plaintexts and their equivalent power samples are stored in different CSV files 
* Simply import your desired class from CorrelationPowerAnalysis.py in your main project as well as Numpy, matplotlib, and pandas
```py
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from CorrelationPowerAnalysis import CpaOnAES128 as CPA
```
* Matplotlib
