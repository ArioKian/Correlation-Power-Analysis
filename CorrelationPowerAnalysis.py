import numpy as np
import matplotlib.pyplot as plt
import sys
import os
from progress.spinner import MoonSpinner

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
        self.correctKey = None
        self.plainTextsTemp = None
        self.powerTracesTemp = None
        self.hypothesisMatrix = None
        self.correlationMatrix = None
        self.maxCorrForEachKeyHypo = None
        self.gradualMaxCorrForEachKeyHypo = []
        self.stepSizes = []
        self.recoveredKeys = np.full(16, np.nan)
        self.correlarionForKeyRecovered = None
        self.progressBarEnabled = False

    def enableProgressBar(self):
        self.progressBarEnabled = True
    
    def disableProgressBar(self):
        self.progressBarEnabled = False
    
    def GetKey(self):
        return self.key        
        
    def SetPowerTraces(self, powerTraces):
        self.powerTraces = powerTraces

    def SetPlainTexts(self, plainTexts):
        self.plainTexts = plainTexts

    def SetCorrectKey(self, correctKey):
        self.correctKey = correctKey

    def GetCorrectKey(self):
        return self.correctKey

    def GetPlainTexts(self):
        return self.plainTexts

    def GetPowerTraces(self):
        return self.powerTraces

    def GetRecoveredKeys(self):
        return self.recoveredKeys
    
    def Sbox(self, inp):
        return self.sboxTable[inp]

    def HammingWeight(self, num):
        return bin(num).count("1")

    def HammingDistance(self, num1, num2):
        return self.HammingWeight(num1^num2)

    def CreateHypothesisMatrix(self, byteNumber):
        print(f"Creating Hypothesis Matrix (Byte Number {byteNumber+1}):")
        keyHypo = [i for i in range(256)]
        self.hypothesisMatrix = np.zeros((len(self.plainTexts), len(keyHypo)))
        with MoonSpinner('Processing…') as bar:
            for i in range(len(self.plainTexts)):
                for j in range(len(keyHypo)):
                    sboxResult = self.Sbox(self.plainTexts[i][byteNumber] ^ keyHypo[j])
                    self.hypothesisMatrix[i][j] = self.HammingWeight(sboxResult)
                bar.next()
                if(self.progressBarEnabled):
                    self.ProgressBar(i,len(self.plainTexts)-1)
            if(self.progressBarEnabled):
                print("")

    def GradualCreateHypothesisMatrix(self, byteNumber, numOfTracesUsed):
        print(f"Creating Hypothesis Matrix For {numOfTracesUsed} Number Of Traces (Byte Number {byteNumber+1}):")
        keyHypo = [i for i in range(256)]
        self.hypothesisMatrix = np.zeros((len(self.plainTextsTemp), len(keyHypo)))
        with MoonSpinner('Processing…') as bar:
            for i in range(len(self.plainTextsTemp)):
                for j in range(len(keyHypo)):
                    sboxResult = self.Sbox(self.plainTextsTemp[i][byteNumber] ^ keyHypo[j])
                    self.hypothesisMatrix[i][j] = self.HammingWeight(sboxResult)
                bar.next()
                if(self.progressBarEnabled):
                    self.ProgressBar(i,len(self.plainTextsTemp)-1)
            if(self.progressBarEnabled):
                print("")


    def NumpyPearsonCorrelation(self, h , p):
        return np.corrcoef(h , p)[0][1]

    def CreateCorrelationMatrix(self):
        print("Creating Correlation Matrix:")
        self.correlationMatrix = np.zeros([256,self.powerTraces.shape[1]])
        with MoonSpinner('Processing…') as bar:
            for i in range(256):
                for j in range(self.powerTraces.shape[1]):
                    self.correlationMatrix[i][j] = self.NumpyPearsonCorrelation(self.hypothesisMatrix[:,i] , self.powerTraces[:,j])
                bar.next()
                if(self.progressBarEnabled):
                    self.ProgressBar(i,255)
            if(self.progressBarEnabled):
                print("")    


    def GradualCreateCorrelationMatrix(self, numOfTracesUsed):
        print(f"Creating Correlation Matrix For {numOfTracesUsed} Number of Traces:")
        self.correlationMatrix = np.zeros([256,self.powerTracesTemp.shape[1]])
        with MoonSpinner('Processing…') as bar:
            for i in range(256):
                for j in range(self.powerTracesTemp.shape[1]):
                    self.correlationMatrix[i][j] = self.NumpyPearsonCorrelation(self.hypothesisMatrix[:,i] , self.powerTracesTemp[:,j])
                bar.next()
                if(self.progressBarEnabled):
                    self.ProgressBar(i,255)
            if(self.progressBarEnabled):
                print("")

    

    def FindMaxCorrValueForEachKeyHypo(self):
        print("Analyzing...")
        self.maxCorrForEachKeyHypo = np.zeros([256])
        with MoonSpinner('Processing…') as bar:
            for i in range(256):
                maxCorrValIndex = np.argmax(abs(self.correlationMatrix[i]))
                self.maxCorrForEachKeyHypo[i]=self.correlationMatrix[i][maxCorrValIndex]
                bar.next()
                if(self.progressBarEnabled):
                    self.ProgressBar(i,255)
            if(self.progressBarEnabled):
                print("")

    def FindKeyHypoWithMaxCorr(self):
        KeyVal = np.argmax(abs(self.maxCorrForEachKeyHypo))
        self.correlarionForKeyRecovered = self.correlationMatrix[KeyVal]
        #print("correlarionForKeyRecovered: ", self.correlarionForKeyRecovered)
        if(self.isAllKeyBytes):
            self.allKeyBytes.append(KeyVal)
        if(self.isFirstKeyByte):
            self.firstKeyByte = KeyVal
        if(self.isNthKeyByte):
            self.nthKeyByte = KeyVal

    def PlotCorrelationGraph(self, targetByte=None):   
        self.CheckOutputsDirectory()
        
        xmax = np.argmax(abs(self.maxCorrForEachKeyHypo))
        ymax = self.maxCorrForEachKeyHypo[xmax]
        ymin = self.maxCorrForEachKeyHypo.min()

        correctKeyPlot = np.zeros(self.maxCorrForEachKeyHypo.shape[0])
        correctKeyPlot[self.correctKey[targetByte-1]] = self.maxCorrForEachKeyHypo[self.correctKey[targetByte-1]]

        recoveredKeyPlot = np.zeros(self.maxCorrForEachKeyHypo.shape[0])
        recoveredKeyPlot[xmax]=ymax

        fig, (ax1,ax2) = plt.subplots(2,1,figsize=(12, 8))
        ax1.set_title(f"Final Correlation Value for Each Key Hypothesis (Byte Number {targetByte})")
        ax1.set_xlabel("Key Byte Hypothesis")
        ax1.set_ylabel("correlation value")
        ax1.set_ylim(ymin+(ymin/2), ymax+(ymax/2))
        markerline1, stemline1, baseline1, = ax1.stem(self.maxCorrForEachKeyHypo, linefmt='-', basefmt='C2-')
        markerline3, stemline3, baseline3, =ax1.stem(correctKeyPlot, linefmt='green', markerfmt='.' , label="ExpectedKey", basefmt='C2-')
        markerline2, stemline2, baseline2, =ax1.stem(recoveredKeyPlot, linefmt='red', markerfmt='.' , label="RecoveredKey", basefmt='C2-')
        # leg = ax1.legend(bbox_to_anchor=(0.75, 1.15), ncol=2)
        # leg = ax1.legend(loc="upper left")

        text= "RecoveredKeyValue={}, CorrValue={:.3f}".format(xmax, ymax)
        bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
        arrowprops=dict(arrowstyle="->",connectionstyle="angle,angleA=0,angleB=60")
        kw = dict(xycoords='data',textcoords="axes fraction",
                  arrowprops=arrowprops, bbox=bbox_props, ha="right", va="top")
        ax1.annotate(text, xy=(xmax, ymax), xytext=(0.99,0.99), **kw)

        text= "ExpectedKey={}".format(self.correctKey[targetByte-1])
        bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
        # arrowprops=dict(arrowstyle="->",connectionstyle="angle,angleA=180,angleB=60")
        arrowprops=dict(arrowstyle="->")
        kw = dict(xycoords='data',textcoords="axes fraction",
                  arrowprops=arrowprops, bbox=bbox_props, ha="left", va="bottom")
        ax1.annotate(text, xy=(self.correctKey[targetByte-1], correctKeyPlot[self.correctKey[targetByte-1]]), xytext=(0.01,0.01), **kw)

        ax2.set_title("Correlation Value for Each Time Sample For the Recovered Key\n(Shows Main Leakage Points)")
        ax2.set_xlabel("Power Trace Time Sample Points")
        ax2.set_ylabel("correlation value")
        ax2.stem(self.correlarionForKeyRecovered)
        
        fig.suptitle("CPA Output using HW Leakage Model")
        fig.subplots_adjust(hspace=0.5)

        # plt.setp(markerline1, markersize = 3)
        plt.setp(stemline1, linewidth = 1.2)
        # plt.setp(markerline2, markersize = 8)
        plt.setp(stemline2, linewidth = 1.2)
        # plt.setp(markerline3, markersize = 8)
        plt.setp(stemline3, linewidth = 4)
        
        plt.savefig("./Outputs/cpaSingleRunOutput_Byte{targetByte}.jpg")
        plt.savefig("./Outputs/cpaSingleRunOutput_Byte{targetByte}.pdf")
        plt.show()
        

    
    def PlotGradualCorrelationGraph(self, targetByte=None):
        self.CheckOutputsDirectory()
        
        # xmax = np.argmax(self.maxCorrForEachKeyHypo)
        # ymax = self.maxCorrForEachKeyHypo.max()
        # ymin = self.maxCorrForEachKeyHypo.min()

        # fig, (ax1,ax2) = plt.subplots(2,1,figsize=(12, 8))
        # ax1.set_title(f"Final Correlation Value for Each Key Hypothesis (Byte Number {targetByte})")
        # ax1.set_xlabel("Key Byte Hypothesis")
        # ax1.set_ylabel("Correlation Value")
        # ax1.set_ylim(ymin-0.2, ymax+0.2)
        # ax1.stem(self.maxCorrForEachKeyHypo)

        xmax = np.argmax(abs(self.maxCorrForEachKeyHypo))
        ymax = self.maxCorrForEachKeyHypo[xmax]
        ymin = self.maxCorrForEachKeyHypo.min()

        correctKeyPlot = np.zeros(self.maxCorrForEachKeyHypo.shape[0])
        correctKeyPlot[self.correctKey[targetByte-1]] = self.maxCorrForEachKeyHypo[self.correctKey[targetByte-1]]

        recoveredKeyPlot = np.zeros(self.maxCorrForEachKeyHypo.shape[0])
        recoveredKeyPlot[xmax]=ymax

        fig, (ax1,ax2) = plt.subplots(2,1,figsize=(12, 8))
        ax1.set_title(f"Final Correlation Value for Each Key Hypothesis (Byte Number {targetByte})")
        ax1.set_xlabel("Key Byte Hypothesis")
        ax1.set_ylabel("correlation value")
        ax1.set_ylim(ymin+(ymin/2), ymax+(ymax/2))
        markerline1, stemline1, baseline1, = ax1.stem(self.maxCorrForEachKeyHypo, linefmt='-', basefmt='C2-')
        markerline3, stemline3, baseline3, =ax1.stem(correctKeyPlot, linefmt='green', markerfmt='.' , label="ExpectedKey", basefmt='C2-')
        markerline2, stemline2, baseline2, =ax1.stem(recoveredKeyPlot, linefmt='red', markerfmt='.' , label="RecoveredKey", basefmt='C2-')
        # leg = ax1.legend(bbox_to_anchor=(0.75, 1.15), ncol=2)
        # leg = ax1.legend(loc="upper left")

        text= "KeyValue={}, CorrValue={:.3f}".format(xmax, ymax)
        bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
        arrowprops=dict(arrowstyle="->",connectionstyle="angle,angleA=0,angleB=60")
        kw = dict(xycoords='data',textcoords="axes fraction",
                  arrowprops=arrowprops, bbox=bbox_props, ha="right", va="top")
        ax1.annotate(text, xy=(xmax, ymax), xytext=(0.99,0.99), **kw)

        text= "ExpectedKey={}".format(self.correctKey[targetByte-1])
        bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
        # arrowprops=dict(arrowstyle="->",connectionstyle="angle,angleA=180,angleB=60")
        arrowprops=dict(arrowstyle="->")
        kw = dict(xycoords='data',textcoords="axes fraction",
                  arrowprops=arrowprops, bbox=bbox_props, ha="left", va="bottom")
        ax1.annotate(text, xy=(self.correctKey[targetByte-1], correctKeyPlot[self.correctKey[targetByte-1]]), xytext=(0.01,0.01), **kw)
        
        
        ax2.set_title("Gradual Correlation Value for Each Hypothesis")
        ax2.set_xlabel("Number of Traces Used")
        ax2.set_ylabel("Correlation Value")
        
        gradualCorrForEachKeyHypo = np.zeros([256,len(self.gradualMaxCorrForEachKeyHypo)])
        for j in range(256):
            for i in range(len(self.gradualMaxCorrForEachKeyHypo)):
                gradualCorrForEachKeyHypo[j][i]= (self.gradualMaxCorrForEachKeyHypo)[i][j]

        for i in range(256):
            ax2.plot(self.stepSizes, gradualCorrForEachKeyHypo[i], color="gray")
        ax2.plot(self.stepSizes, gradualCorrForEachKeyHypo[self.correctKey[targetByte-1]], color="green",linewidth=5, alpha=0.5, label="expected Key")
        ax2.plot(self.stepSizes, gradualCorrForEachKeyHypo[xmax], color="red", label="recovered Key")
        leg = ax2.legend(loc="upper right")
        
        fig.subplots_adjust(hspace=0.5)
        fig.suptitle("Gradual CPA Output using HW Leakage Model")
        
        # plt.setp(markerline1, markersize = 3)
        plt.setp(stemline1, linewidth = 1.2)
        # plt.setp(markerline2, markersize = 8)
        plt.setp(stemline2, linewidth = 1.2)
        # plt.setp(markerline3, markersize = 8)
        plt.setp(stemline3, linewidth = 4)
        
        plt.savefig(f"./Outputs/cpaGradualRunOutput_Byte{targetByte}.jpg")
        plt.savefig(f"./Outputs/cpaGradualRunOutput_Byte{targetByte}.pdf")
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
        self.recoveredKeys[0] = self.firstKeyByte
        self.PlotCorrelationGraph(1)


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
            self.GradualCreateHypothesisMatrix(0 , numOfTracesUsed)
            self.GradualCreateCorrelationMatrix(numOfTracesUsed)
            self.FindMaxCorrValueForEachKeyHypo()
            self.gradualMaxCorrForEachKeyHypo.append(self.maxCorrForEachKeyHypo)
            currentStepSize = currentStepSize + stepSize
            self.stepSizes.append(currentStepSize)
            self.FindKeyHypoWithMaxCorr()
            print(f"First Key Byte Value for {numOfTracesUsed} number of traces: Dec: {self.firstKeyByte}, Hex: {hex(self.firstKeyByte)}")
        print(f"First Key Byte Value: Dec: {self.firstKeyByte}, Hex: {hex(self.firstKeyByte)}")
        self.recoveredKeys[0] = self.firstKeyByte
        self.PlotGradualCorrelationGraph(1)
        


    def CpaOnDesiredKeyByte(self, keyByteNum):
        self.isFirstKeyByte = False
        self.isAllKeyBytes = False
        self.isNthKeyByte = True
        self.CreateHypothesisMatrix(keyByteNum-1)
        self.CreateCorrelationMatrix()
        self.FindMaxCorrValueForEachKeyHypo()
        self.FindKeyHypoWithMaxCorr()
        print(f"Key Byte Num{keyByteNum} Value: Dec: {self.nthKeyByte}, Hex: {hex(self.nthKeyByte)}")
        #plt.plot(self.maxCorrForEachKeyHypo)
        self.recoveredKeys[keyByteNum-1] = self.nthKeyByte
        self.PlotCorrelationGraph(keyByteNum)


    def GradualCpaOnDesiredKeyByte(self, keyByteNum, stepSize):
        self.isFirstKeyByte = False
        self.isAllKeyBytes = False
        self.isNthKeyByte = True
        self.gradualMaxCorrForEachKeyHypo = []
        self.stepSizes = []
        currentStepSize = 0
        for numOfTracesUsed in range(stepSize,len(self.plainTexts),stepSize):
            print(f"Running CPA with {numOfTracesUsed} number of traces")
            self.plainTextsTemp = np.zeros([numOfTracesUsed,self.plainTexts.shape[1]])
            self.plainTextsTemp = self.plainTexts[0:numOfTracesUsed,:]
            self.powerTracesTemp = np.zeros([numOfTracesUsed,self.powerTraces.shape[1]])
            self.powerTracesTemp = self.powerTraces[0:numOfTracesUsed,:]
            self.GradualCreateHypothesisMatrix(keyByteNum-1, numOfTracesUsed)
            self.GradualCreateCorrelationMatrix(numOfTracesUsed)
            self.FindMaxCorrValueForEachKeyHypo()
            self.gradualMaxCorrForEachKeyHypo.append(self.maxCorrForEachKeyHypo)
            currentStepSize = currentStepSize + stepSize
            self.stepSizes.append(currentStepSize)
            self.FindKeyHypoWithMaxCorr()
            print(f"Key Byte Num{keyByteNum} Value for {numOfTracesUsed} number of traces: Dec: {self.nthKeyByte}, Hex: {hex(self.nthKeyByte)}")
        print(f"Key Byte Num{keyByteNum} Value: Dec: {self.nthKeyByte}, Hex: {hex(self.nthKeyByte)}")
        self.recoveredKeys[keyByteNum-1] = self.nthKeyByte
        self.PlotGradualCorrelationGraph(keyByteNum)
        

    def ProgressBar(self, count_value, total, suffix=''):
        bar_length = 100
        filled_up_Length = int(round(bar_length* count_value / float(total)))
        percentage = round(100.0 * count_value/float(total),1)
        bar = '=' * filled_up_Length + '-' * (bar_length - filled_up_Length)
        sys.stdout.write('[%s] %s%s ...%s\r' %(bar, percentage, '%', suffix))
        sys.stdout.flush()


    def DeleteFilesInDirectory(self, directoryPath):
        try:
            files = os.listdir(directoryPath)
            for file in files:
                filePath = os.path.join(directoryPath, file)
                if os.path.isfile(filePath):
                    os.remove(filePath)
            print("All previous output files deleted successfully.")
        except OSError:
            print("Error occurred while deleting previous output files.")


    def CheckOutputsDirectory(self):
        isDirExist = os.path.exists('Outputs')
        if isDirExist:
            self.DeleteFilesInDirectory('./Outputs')
        else:
            os.makedirs('Outputs')
        