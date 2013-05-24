#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct attr_req_in
{
	unsigned long timestamp;
	char *dn;
	char *service;
	int required_attr_len;
	char **required_attr;
	int requested_attr_len;
	char **requested_attr;
} ATTR_REQ_IN;

ATTR_REQ_IN *parse_attr_req(char *input, int len)
{
	ATTR_REQ_IN *tmp_attr_req = malloc(sizeof(ATTR_REQ_IN));
	int input_cur = 0;
	
	char item_tmp[STR_MAXLEN];
	int item_len = 0;
	int attr_p = 0;
	
	int state = STATE_TIMESTAMP;
	
	while(input_cur < len)
	{
		switch (state)
		{
			case STATE_TIMESTAMP:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->timestamp = strtol(item_tmp, NULL, 10);
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_DN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->dn = malloc(sizeof(char) * (item_cur + 1));
					memcpy(tmp_attr_req->dn, item_tmp, sizeof(char) * (item_cur + 1));
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUIRED_ATTR_LEN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->required_attr_len = (int) strtol(item_tmp, NULL, 10);
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUIRED_ATTR:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					
					if (attr_p == 0)
					{
						tmp_attr_req->required_attr = malloc(sizeof(char *));
						tmp_attr_req.required_attr[attr_p] = malloc(sizeof(char) * (item_cur + 1));
					}
					else
					{
						tmp_attr_req->required_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1));
						tmp_attr_req.required_attr[attr_p] = malloc(sizeof(char) * (item_cur + 1));
					}

					memcpy(tmp_attr_req.required_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
					attr_p++;
					
					if (attr_p >= tmp_attr_req->required_attr_len)
					{
						state++;
						attr_p = 0;
					}
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUESTED_ATTR_LEN:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					tmp_attr_req->requested_attr_len = (int) strtol(item_tmp, NULL, 10);
					state++;
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
			case STATE_REQUESTED_ATTR:
				if (input[input_cur] == ':')
				{
					item_tmp[item_cur] = '\0';
					
					if (attr_p == 0)
					{
						tmp_attr_req->requested_attr = mallooc(sizeof(char *));
						tmp_attr_req.requested_attr[attr_p] = malloc(sizeof(char) * (item_cur + 1));
					}
					else
					{
						tmp_attr_req->requested_attr = realloc(tmp_attr_req->required_attr, sizeof(char *) * (attr_p + 1));
						tmp_attr_req.requested_attr[attr_p] = malloc(sizeof(char) * (item_cur + 1));
					}

					
					memcpy(tmp_attr_req.requested_attr[attr_p], item_tmp, sizeof(char) * (item_cur + 1));
					attr_p++;
					
					if (attr_p >= tmp_attr_req->requested_attr_len)
					{
						state++;
						attr_p = 0;
					}
					input_cur++;
					bzero(item_tmp, sizeof(char) * STR_MAXLEN);
					tmp_cur = 0;
					break;
				}
				item_tmp[item_cur] = input[input_cur];
				item_cur++;
				input_cur++;
				break;
		}
	}

	return tmp_attr_req;
}

int main(void)
{
	char *input = "12345:DC=HVA,DC=NL,CN=VOMS-SERVICE:2:UserName:Password:1:ResearchGroup"
	int input_len = strlen(input);
	ATTR_REQ_IN *mystruct = parse_attr_req(input, input_len);
	
	printf("%l\n", mystruct->timestamp);
}