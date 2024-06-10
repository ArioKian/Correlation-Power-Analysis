import numpy as np
import matplotlib.pyplot as plt

class CpaOnAES128:
    sboxTable = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    )
    
    def __init__(self):
        self.allKeyBytes = []
        self.firstKeyByte = None
        self.nthKeyByte = None
        self.isAllKeyBytes = False
        self.isFirstKeyByte = False
        self.isNthKeyByte = False
        self.plainTexts = None
        self.powerTraces = None
        self.plainTextsTemp = None
        self.powerTracesTemp = None
        self.hypothesisMatrix = None
        self.correlationMatrix = None
        self.maxCorrForEachKeyHypo = None
        self.gradualMaxCorrForEachKeyHypo = []
        self.stepSizes = []
    
    def GetKey(self):
        return self.key        
        
    def SetPowerTraces(self, powerTraces):
        self.powerTraces = powerTraces

    def SetPlainTexts(self, plainTexts):
        self.plainTexts = plainTexts

    def GetPlainTexts(self):
        return self.plainTexts

    def GetPowerTraces(self):
        return self.powerTraces

    def Sbox(self, inp):
        return self.sboxTable[inp]

    def HammingWeight(self, num):
        return bin(num).count("1")

    def HammingDistance(self, num1, num2):
        return self.HammingWeight(num1^num2)

    def CreateHypothesisMatrix(self, byteNumber):
        keyHypo = [i for i in range(256)]
        self.hypothesisMatrix = np.zeros((len(self.plainTexts), len(keyHypo)))
        for i in range(len(self.plainTexts)):
            for j in range(len(keyHypo)):
                sboxResult = self.Sbox(self.plainTexts[i][byteNumber] ^ keyHypo[j])
                self.hypothesisMatrix[i][j] = self.HammingWeight(sboxResult)


    def GradualCreateHypothesisMatrix(self, byteNumber):
        keyHypo = [i for i in range(256)]
        self.hypothesisMatrix = np.zeros((len(self.plainTextsTemp), len(keyHypo)))
        for i in range(len(self.plainTextsTemp)):
            for j in range(len(keyHypo)):
                sboxResult = self.Sbox(self.plainTextsTemp[i][byteNumber] ^ keyHypo[j])
                self.hypothesisMatrix[i][j] = self.HammingWeight(sboxResult)


    def NumpyPearsonCorrelation(self, h , p):
        return np.corrcoef(h , p)[0][1]

    def CreateCorrelationMatrix(self):
        self.correlationMatrix = np.zeros([256,self.powerTraces.shape[1]])
        for i in range(256):
            for j in range(self.powerTraces.shape[1]):
                self.correlationMatrix[i][j] = self.NumpyPearsonCorrelation(self.hypothesisMatrix[:,i] , self.powerTraces[:,j])


    def GradualCreateCorrelationMatrix(self):
        self.correlationMatrix = np.zeros([256,self.powerTracesTemp.shape[1]])
        for i in range(256):
            for j in range(self.powerTracesTemp.shape[1]):
                self.correlationMatrix[i][j] = self.NumpyPearsonCorrelation(self.hypothesisMatrix[:,i] , self.powerTracesTemp[:,j])

    

    def FindMaxCorrValueForEachKeyHypo(self):
        self.maxCorrForEachKeyHypo = np.zeros([256])
        for i in range(256):
            maxCorrValIndex = np.argmax(abs(self.correlationMatrix[i]))
            self.maxCorrForEachKeyHypo[i]=self.correlationMatrix[i][maxCorrValIndex]

    def FindKeyHypoWithMaxCorr(self):
        KeyVal = np.argmax(abs(self.maxCorrForEachKeyHypo))
        if(self.isAllKeyBytes):
            self.allKeyBytes.append(KeyVal)
        if(self.isFirstKeyByte):
            self.firstKeyByte = KeyVal
        if(self.isNthKeyByte):
            self.nthKeyByte = KeyVal


    
    def PlotGradualCorrelationGraph(self):

        xmax = np.argmax(self.maxCorrForEachKeyHypo)
        ymax = self.maxCorrForEachKeyHypo.max()
        ymin = self.maxCorrForEachKeyHypo.min()

        fig, (ax1,ax2) = plt.subplots(2,1,figsize=(8, 8))
        ax1.set_title("Final Correlation Value for Each Hypothesis")
        ax1.set_xlabel("Key Byte Hypothesis")
        ax1.set_ylabel("correlation value")
        ax1.set_ylim(ymin-0.2, ymax+0.2)
        ax1.stem(self.maxCorrForEachKeyHypo)

        text= "x={}, y={:.3f}".format(xmax, ymax)
        bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
        arrowprops=dict(arrowstyle="->",connectionstyle="angle,angleA=0,angleB=60")
        kw = dict(xycoords='data',textcoords="axes fraction",
                  arrowprops=arrowprops, bbox=bbox_props, ha="right", va="top")
        ax1.annotate(text, xy=(xmax, ymax), xytext=(0.99,0.99), **kw)
        ax2.set_title("Gradual Correlation Value for Each Hypothesis")
        ax2.set_xlabel("Number of Traces Used")
        ax2.set_ylabel("correlation value")
        
        gradualCorrForEachKeyHypo = np.zeros([256,len(self.gradualMaxCorrForEachKeyHypo)])
        for j in range(256):
            for i in range(len(self.gradualMaxCorrForEachKeyHypo)):
                gradualCorrForEachKeyHypo[j][i]= (self.gradualMaxCorrForEachKeyHypo)[i][j]

        for i in range(256):
            if i==xmax:
                ax2.plot(self.stepSizes, gradualCorrForEachKeyHypo[i], color="red")  
            else:
                ax2.plot(self.stepSizes, gradualCorrForEachKeyHypo[i], color="gray")
        fig.subplots_adjust(hspace=0.5)
        plt.figure(figsize=(100,60))
        plt.show()
    

    
    def CpaOnFirstKeyByte(self):
        self.isFirstKeyByte = True
        self.isAllKeyBytes = False
        self.isNthKeyByte = False
        self.CreateHypothesisMatrix(0)
        self.CreateCorrelationMatrix()
        self.FindMaxCorrValueForEachKeyHypo()
        self.FindKeyHypoWithMaxCorr()
        print(f"First Key Byte Value: Dec: {self.firstKeyByte}, Hex: {hex(self.firstKeyByte)}")
        #plt.plot(self.maxCorrForEachKeyHypo)


    def GradualCpaOnFirstKeyByte(self, stepSize):
        self.isFirstKeyByte = True
        self.isAllKeyBytes = False
        self.isNthKeyByte = False
        self.gradualMaxCorrForEachKeyHypo = []
        self.stepSizes = []
        currentStepSize = 0
        for numOfTracesUsed in range(stepSize,len(self.plainTexts),stepSize):
            print(f"Running CPA with {numOfTracesUsed} number of traces")
            self.plainTextsTemp = np.zeros([numOfTracesUsed,self.plainTexts.shape[1]])
            self.plainTextsTemp = self.plainTexts[0:numOfTracesUsed,:]
            self.powerTracesTemp = np.zeros([numOfTracesUsed,self.powerTraces.shape[1]])
            self.powerTracesTemp = self.powerTraces[0:numOfTracesUsed,:]
            self.GradualCreateHypothesisMatrix(0)
            self.GradualCreateCorrelationMatrix()
            self.FindMaxCorrValueForEachKeyHypo()
            self.gradualMaxCorrForEachKeyHypo.append(self.maxCorrForEachKeyHypo)
            currentStepSize = currentStepSize + stepSize
            self.stepSizes.append(currentStepSize)
            self.FindKeyHypoWithMaxCorr()
            print(f"First Key Byte Value for {numOfTracesUsed} number of traces: Dec: {self.firstKeyByte}, Hex: {hex(self.firstKeyByte)}")
        print(f"First Key Byte Value: Dec: {self.firstKeyByte}, Hex: {hex(self.firstKeyByte)}")
        self.PlotGradualCorrelationGraph()
        


    def CpaOnDesiredKeyByte(self, keyByteNum):
        self.isFirstKeyByte = False
        self.isAllKeyBytes = False
        self.isNthKeyByte = True
        self.CreateHypothesisMatrix(keyByteNum-1)
        self.CreateCorrelationMatrix()
        self.FindMaxCorrValueForEachKeyHypo()
        self.FindKeyHypoWithMaxCorr()
        print(f"Key Byte Num{keyByteNum} Value: Dec: {self.nthKeyByte}, Hex: {hex(self.nthKeyByte)}")
        plt.plot(self.maxCorrForEachKeyHypo)

