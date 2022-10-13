# CMDiagnostor 
CMDiagnostor is an ambiguity-aware root cause localization approach based on Call Metric Data

- data field description
    | field | description | example(desensitization) |
    | ------ | ------| ------|
    | monitor_id | ID of monitoring item | 69892594 |
    | caller_server | service name of caller | 9423f6fd8f687835be9ad98a4bcc408e |
    | caller_service | service port of caller | d43783eadc757a7e8a8b82af3170536b |
    | caller_method | method of caller | 9b095c8ef97a1dc8133cc65fbf562bea |
    | caller_set | custom tags of caller | d79821eb11343daa4641187d09aaae51 |
    | callee_server | service name of callee | 9423f6fd8f687835be9ad98a4bcc408e |
    | callee_service | service port of callee | d170a67d8c056b36ce038830701d9c3c |
    | callee_method | method of callee | ac126830fb14a85d85c2475676bb420a |
    | callee_set | custom tags of callee | d79821eb11343daa4641187d09aaae51 |
    | request_min_map | total call count per minute in a certain day | 0:207,1:570,2:558,...,1438:276,1439:127 |
    | duration_min_map | total call duration per minute in a certain day | 0:33,1:41,2:32,...,1438:69,1439:37 |
    | success_min_map | successful call count per minute in a certain day | 0:204,1:565,2:551,...,1438:267,1439:116 |
    | exception_min_map | exceptional call count per minute in a certain day | 0:1,1:2,2:3,...,1438:4,1439:5 |
    | timeout_min_map | overtime call count per minute in a certain day | 0:2,1:3,2:4,...,1438:5,1439:6 |

    - instruction:
      - average response time = duration / request
      - error count = exception + timeout
    
- data example
  
  ```
  69892594|9423f6fd8f687835be9ad98a4bcc408e|d43783eadc757a7e8a8b82af3170536b|9b095c8ef97a1dc8133cc65fbf562bea|d79821eb11343daa4641187d09aaae51|9423f6fd8f687835be9ad98a4bcc408e|d170a67d8c056b36ce038830701d9c3c|ac126830fb14a85d85c2475676bb420a|d79821eb11343daa4641187d09aaae51|0:207,1:570,2:558,...,1438:276,1439:127|0:33,1:41,2:32,...,1438:69,1439:37|0:204,1:565,2:551,...,1438:267,1439:116|0:1,1:2,2:3,...,1438:4,1439:5|0:2,1:3,2:4,...,1438:5,1439:6
  69898584|5f09e43f763a024f26daffe60f7962ed|d43783eadc757a7e8a8b82af3170536b|d79821eb11343daa4641187d09aaae51|d79821eb11343daa4641187d09aaae51|29de4931c91a8541d9ff26133179966e|d79821eb11343daa4641187d09aaae51|9ff4ab9daf9ec5960903a7e631301437|d79821eb11343daa4641187d09aaae51|0:207,1:570,2:558,...,1438:276,1439:127|0:33,1:41,2:32,...,1438:69,1439:37|0:204,1:565,2:551,...,1438:267,1439:116|0:1,1:2,2:3,...,1438:4,1439:5|0:2,1:3,2:4,...,1438:5,1439:6
  ```
  
- the requirements are listed in the txt file and the Python version is 3.10.0