import json, re
from junit_xml import TestSuite, TestCase

with open('retire_result_32.json') as f:
    json_data = json.load(f)

failure_body = ''
test_cases_list = []
for file_element in json_data['data'] :
    #print(json.dumps(file_element, indent = 4, sort_keys=False),"\n------------")
    file_name = file_element['file']
    print(file_name,"\n----")
    count = 0
    for result_element in file_element['results'] :
        print('result_element :: ',result_element)
        print('count ::',count)
        count +=1
	#print('result_element[4] :: ',result_element[4])
        #print('vulnerabilities :: ',result_element[vulnerabilities])
        for vulnerability_ele in result_element["vulnerabilities"]:
            #print('Vulnerability :: ',vulnerability_ele)
            cve_message = vulnerability_ele['identifiers']['CVE'][0]
            info_text = vulnerability_ele['info']
            #info_text = (*vulnerability_ele['info'], sep = "\n")
            severity_classname = vulnerability_ele['severity']
            #print("file_name : ", file_name)
            #print("cve_message : ", cve_message)
            #print("info_text : ", info_text)
            #print("info_text : ", str(info_text))
            #print("info_text : ", *info_text, sep = "\n")
            #print("severity_classname : ",severity_classname,"\n----")

            info_text2 = re.sub(r"^\[","",str(info_text))
#            info_text2 = re.sub(r"^\[","",str(info_text).replace("\', \'","\',\n\'").replace('\'',"\""))
            info_text3 = re.sub(r"\]$","",info_text2)

            failure_body = str(file_name)+"\n"+str(info_text3)
            test_case = TestCase('Test1', None, 0)
            test_case.add_failure_info(message=cve_message, output=failure_body)
            test_cases_list.append(test_case)

ts = TestSuite("my test suite", test_cases_list)
# pretty printing is on by default but can be disabled using prettyprint=False
print(TestSuite.to_xml_string([ts]))

with open('junit_xml_output.xml', 'w') as f:
    TestSuite.to_file(f, [ts], prettyprint=False)
