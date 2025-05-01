#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Any, Optional, List

def message_handler(message: Dict[str, Any], logger, task_parameter: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:    
    event_type = message.get('event_type')
    info = message.get('hasErrors', {})
    fileName = info.get('fileName', None)
    hasErrors = info.get('hasErrors', None)
    content = info.get('content', None)
    expected_file_content = task_parameter.get("expected_file_content", "importargparseimportcollectionsimportdatetimeimportfunctoolsimportjsonimportloggingimportmathimportnumpyimportosimportpandasimportpathlibimportrandomimportreimportrequestsimportsqlite3importsysimporttimelogging.basicConfig(level=logging.INFO,format='%(asctime)s-%(levelname)s-%(message)s')@functools.lru_cache(maxsize=128)deffetch_data(url):try:logging.info(f'Fetchingdatafrom{url}')response=requests.get(url)response.raise_for_status()returnresponse.json()exceptrequests.RequestExceptionase:logging.error(f'Requestfailed:{e}')sys.exit(1)defclean_and_transform(data):df=pandas.DataFrame(data)df=df.dropna()df['timestamp']=pandas.to_datetime(df['created_at'],errors='coerce')df['word_count']=df['text'].apply(lambdax:len(str(x).split()))returndfdefanalyze(df):logging.info('Analyzingdata...')avg_words=df['word_count'].mean()top_words=collections.Counter(''.join(df['text']).split()).most_common(5)returnavg_words,top_wordsdefsave_to_sqlite(df,db_path='data.db'):conn=sqlite3.connect(db_path)df.to_sql('api_data',conn,if_exists='replace',index=False)conn.close()logging.info('DatasavedtoSQLite')defsave_to_file(df,out_dir='output'):os.makedirs(out_dir,exist_ok=True)out_path=os.path.join(out_dir,f'data_{datetime.date.today()}.json')df.to_json(out_path,orient='records',indent=2)logging.info(f'Datasavedto{out_path}')defmain():parser=argparse.ArgumentParser(description='ProcessAPIdata')parser.add_argument('--url',type=str,required=False,default='https://jsonplaceholder.typicode.com/posts',help='APIURLtofetchJSONdatafrom')args=parser.parse_args()json_data=fetch_data(args.url)ifisinstance(json_data,dict):json_data=[json_data]df=clean_and_transform(json_data)avg,top=analyze(df)logging.info(f'Averagewordsperentry:{avg}')logging.info(f'Top5words:{top}')save_to_sqlite(df)save_to_file(df)logging.info('Scriptfinished.')if__name__=='__main__':main()")
    expected_file_path = task_parameter.get("expected_file_path", "/root/C-Plus-Plus/python_test/sort_import.py")
    logger.info(message.get('message'))
    if event_type == 'evaluate_on_completion' and fileName == expected_file_path and hasErrors == False:
        if ''.join(content.split()) == expected_file_content:
            return [
                {"status": "key_step", "index": 1},
                {"status": "success", "reason": f"任务成功完成"}
            ]
        else:
            return [{"status": "error", "type": "evaluate_on_completion", "message": "任务没有完成"}]
    return None
