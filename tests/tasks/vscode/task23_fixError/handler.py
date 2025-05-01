#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    info = message.get('hasErrors', {})
    fileName = info.get('fileName', None)
    hasErrors = info.get('hasErrors', None)
    content = info.get('content', None)
    expected_file_content = task_parameter.get("expected_file_content", "#include<cmath>#include<complex>#include<iostream>#include<stdexcept>#include<vector>constdoublePI=3.14159265358979323846;classFftCalculator{private:voidbutterflyTransform(std::vector<std::complex<double>>&inputData,boolisInverse){size_tdataSize=inputData.size();if(dataSize<=1)return;if((dataSize&(dataSize-1))!=0){throwstd::invalid_argument(\"Inputsizemustbepowerof2\");}for(size_ti=0,j=0;i<dataSize;++i){if(j>i){std::swap(inputData[i],inputData[j]);}size_tm=dataSize;while(j&(m>>=1)){j&=~m;}j|=m;}for(size_tstage=1;stage<dataSize;stage<<=1){size_thalfSize=stage;size_tstepSize=stage<<1;doubleangleFactor=(isInverse?PI:-PI)/halfSize;for(size_ti=0;i<dataSize;i+=stepSize){for(size_tj=0;j<halfSize;++j){autotwiddleFactor=std::polar(1.0,angleFactor*j);autotemp=inputData[i+j+halfSize]*twiddleFactor;inputData[i+j+halfSize]=inputData[i+j]-temp;inputData[i+j]+=temp;}}}if(isInverse){for(auto&value:inputData){value/=dataSize;}}}public:std::vector<std::complex<double>>computeFft(conststd::vector<double>&inputSignal){size_tsignalSize=inputSignal.size();std::vector<std::complex<double>>complexInput(signalSize);for(size_ti=0;i<signalSize;++i){complexInput[i]=std::complex<double>(inputSignal[i],0.0);}butterflyTransform(complexInput,false);returncomplexInput;}std::vector<std::complex<double>>computeInverseFft(conststd::vector<std::complex<double>>&inputSpectrum){std::vector<std::complex<double>>result=inputSpectrum;butterflyTransform(result,true);returnresult;}};intmain(){try{FftCalculatorfftCalc;std::vector<double>testSignal={1.0,2.0,3.0,4.0,0.0,0.0,0.0,0.0};autofftResult=fftCalc.computeFft(testSignal);autoinverseResult=fftCalc.computeInverseFft(fftResult);for(size_ti=0;i<fftResult.size();++i){std::cout<<\"FFT[\"<<i<<\"]=\"<<fftResult[i]<<\",Inverse[\"<<i<<\"]=\"<<inverseResult[i]<<std::endl;}std::cout<<\"thelengthoftestSignalis\"<<std::endl;std::cout<<testSignal.size()<<std::endl;}catch(conststd::exception&e){std::cerr<<\"Error:\"<<e.what()<<std::endl;return1;}return0;}")
    expected_file_path = task_parameter.get("expected_file_path", "/root/C-Plus-Plus/agent_test/fix_error.cpp")
    logger.info(message)
    if event_type == 'evaluate_on_completion' and fileName == expected_file_path and hasErrors == False:
        if ''.join(content.split()) == expected_file_content:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
