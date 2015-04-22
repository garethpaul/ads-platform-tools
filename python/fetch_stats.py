#!/usr/bin/env python
"""
 Copyright (C) 2015 Twitter Inc and other contributors.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 """

import requests
import oauth2 as oauth
import yaml
import urllib
import json
import os
import time
import pytz
import datetime
import argparse
import re
import sys


DOMAIN = 'https://ads-api.twitter.com'
VERBOSE = 0
NON_SUB_PARAM_SEGMENTATION_TYPES = ['PLATFORMS', 'LOCATIONS', 'GENDER', 'INTERESTS', 'KEYWORDS']

def main(options):
  global VERBOSE
  account = options.account_id
  headers = options.headers
  if options.veryverbose == True:
    VERBOSE = 2
  elif options.verbose == True:
    VERBOSE = 1
  start = time.clock()
  user_twurl = twurlauth()

  print("Best practices stats check for :account_id %s" % account)
  linesep()

  now = datetime.datetime.utcnow()
  start_time = datetime.datetime.utcnow() - datetime.timedelta(days=7)
  start_time = start_time.replace(minute=0, second=0, microsecond=0)
  end_time = datetime.datetime.utcnow()
  end_time = end_time.replace(minute=0, second=0, microsecond=0)
  end_time -= datetime.timedelta(seconds=1)
  print('Current time:\t%s' % now)
  print('Start time:\t%s' % start_time)
  print('End time:\t%s' % end_time)
  linesep()

  # check that we have access to this :account_id
  resource_path = '/0/accounts/%s' % account
  data = get_data(user_twurl, 'GET', headers, DOMAIN + resource_path)

  if len(data) == 0:
    print('ERROR: Could not locate :account_id %s' % account)
    sys.exit(0)

  # fetch funding instruments
  resource_path = '/0/accounts/%s/funding_instruments?with_deleted=true&count=1000' % account
  data = get_data(user_twurl, 'GET', headers, DOMAIN + resource_path)

  # filter funding instruments
  print("Pre-filtered data:\t\t%s" % len(data))
  funding_instruments = check(data, start_time, end_time)
  print("Funding instruments:\t\t%s" % len(funding_instruments))

  # fetch campaigns
  resource_path = '/0/accounts/%s/campaigns?with_deleted=true&count=1000' % account
  data = get_data(user_twurl, 'GET', headers, DOMAIN + resource_path)

  # filter campaigns
  print("Pre-filtered data:\t\t%s" % len(data))
  campaigns = check(data, start_time, end_time, 'funding_instrument_id', funding_instruments)
  print("Campaigns:\t\t\t%s" % len(campaigns))

  # fetch line items
  resource_path = '/0/accounts/%s/line_items?with_deleted=true&count=1000' % account
  data = get_data(user_twurl, 'GET', headers, DOMAIN + resource_path)

  # filter line items
  print("Pre-filtered data:\t\t%s" % len(data))
  line_items = check(data, start_time, end_time, 'campaign_id', campaigns)
  print("Line items:\t\t\t%s" % len(line_items))

  # fetch promoted_tweets
  resource_path = '/0/accounts/%s/promoted_tweets?with_deleted=true&count=1000' % account
  data = get_data(user_twurl, 'GET', headers, DOMAIN + resource_path)

  # filter promoted_tweets
  print("Pre-filtered data:\t\t%s" % len(data))
  promoted_tweets = check(data, start_time, end_time, 'line_item_id', line_items)
  print("Promoted Tweets:\t\t%s" % len(promoted_tweets))

  total_query_count = 0
  total_request_cost = 0
  total_rate_limited_query_count = 0
  segmented_query_count = 0
  segmented_request_cost = 0

  if len(line_items) > 0:
    print("\tfetching stats for %s line items" % len(line_items))
    (query_count, cost_total, rate_limited_query_count) = gather_stats(user_twurl, headers, account, 'line_items',
                                                                       start_time, end_time, line_items)

    total_query_count += query_count
    total_request_cost += cost_total

  if len(promoted_tweets) > 0:
    print("\tfetching stats for %s promoted tweets" % len(promoted_tweets))
    (query_count, cost_total, rate_limited_query_count) = gather_stats(user_twurl, headers, account, 'promoted_tweets',
                                                                       start_time, end_time, promoted_tweets)

    total_query_count += query_count
    total_request_cost += cost_total
    total_rate_limited_query_count += rate_limited_query_count

  # Segmentation queries
  if options.segmentation == True:
    if len(line_items) > 0:
      print("\tfetching segmentation stats for %s line items" % len(line_items))
      for i in NON_SUB_PARAM_SEGMENTATION_TYPES:
        (query_count, cost_total, rate_limited_query_count) = gather_stats(user_twurl, headers, account,
                                                                           'line_items', start_time, end_time,
                                                                           line_items, i)

        total_query_count += query_count
        total_request_cost += cost_total
        segmented_query_count += query_count
        segmented_request_cost += cost_total

    if len(promoted_tweets) > 0:
      print("\tfetching segmentation stats for %s promoted tweets" % len(promoted_tweets))
      for i in NON_SUB_PARAM_SEGMENTATION_TYPES:
        (query_count, cost_total, rate_limited_query_count) = gather_stats(user_twurl, headers, account,
                                                                           'promoted_tweets', start_time,
                                                                           end_time, promoted_tweets, i)

        total_query_count += query_count
        total_request_cost += cost_total
        segmented_query_count += query_count
        segmented_request_cost += cost_total

  linesep()
  if options.segmentation:
    print("Non-Seg Stats Req Cost:\t\t%s" % (total_request_cost - segmented_request_cost))
    print("Segmented Stats Req Cost:\t%s" % segmented_request_cost)
    if VERBOSE > 0:
      print("Avg Cost per Non-Seg Query:\t%s" % str((total_request_cost - segmented_request_cost ) / \
            (total_query_count - segmented_query_count)))
      print("Avg Cost per Segmented Query:\t%s" % str(segmented_request_cost / segmented_query_count))
    linesep()
  print("Total Stats Queries:\t\t%s" % total_query_count)
  print("Total Stats Request Cost:\t%s" % total_request_cost)
  if VERBOSE > 0:
    print("Avg Cost per Query:\t\t%s" % str(total_request_cost / total_query_count))
  print("Queries Rate Limited:\t\t%s" % total_rate_limited_query_count)
  linesep()

  elapsed = (time.clock() - start)
  print('Time elapsed:\t\t\t%s' % elapsed)

def input():
  p = argparse.ArgumentParser(description='Fetch Twitter Ads Account Stats')

  p.add_argument('-a', '--account', required=True, dest='account_id', help='Ads Account ID')
  p.add_argument('-A', '--header', dest='headers', action='append', help='HTTP headers to include')
  p.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='Verbose outputs cost avgs')
  p.add_argument('-vv', '--very-verbose', dest='veryverbose', action='store_true',
                 help='Very verbose outputs API queries made')
  p.add_argument('-s', '--segmentation', dest='segmentation', help='Pull segmentation stats',
                 action='store_true')

  args = p.parse_args()

  return args

def twurlauth():
  """
    Returns the authentication data.
  """
  with open(os.path.expanduser('~/.twurlrc'), 'r') as f:
    contents = yaml.load(f)
    f.close()

  default_user = contents["configuration"]["default_profile"][0]

  CONSUMER_KEY = contents["configuration"]["default_profile"][1]
  CONSUMER_SECRET = contents["profiles"][default_user][CONSUMER_KEY]["consumer_secret"]
  USER_OAUTH_TOKEN = contents["profiles"][default_user][CONSUMER_KEY]["token"]
  USER_OAUTH_TOKEN_SECRET = contents["profiles"][default_user][CONSUMER_KEY]["secret"]

  return CONSUMER_KEY, CONSUMER_SECRET, USER_OAUTH_TOKEN, USER_OAUTH_TOKEN_SECRET

def request(user_twurl, http_method, headers, url):
  """
    Returns data from a single request.
    Args:
        user_twurl = twurlauth()
        http_method = PUT, POST or GET
        headers = http headers
        url = endpoint url
  """
  CONSUMER_KEY=user_twurl[0]
  CONSUMER_SECRET = user_twurl[1]
  USER_OAUTH_TOKEN = user_twurl[2]
  USER_OAUTH_TOKEN_SECRET = user_twurl[3]

  consumer = oauth.Consumer(key=CONSUMER_KEY, secret=CONSUMER_SECRET)
  token = oauth.Token(key=USER_OAUTH_TOKEN, secret=USER_OAUTH_TOKEN_SECRET)
  client = oauth.Client(consumer, token)

  header_list = {}
  if headers:
    for i in headers:
      (key, value) = i.split(': ')
      if key and value:
        header_list[key] = value

  response, content = client.request(url, method = http_method, headers = header_list)

  try:
    data = json.loads(content)
  except:
    data = None
  return response, data

def get_data(user_twurl, http_method, headers, url):
  """
    Returns data from multiple request e.g. cursors
    Args:
        user_twurl = twurlauth()
        http_method = PUT, POST or GET
        headers = http headers
        url = endpoint url
  """
  data = []

  res_headers, response = request(user_twurl, http_method, headers, url)

  if res_headers['status'] != '200':
    print('ERROR: query failed, cannot continue: %s' % url)
    sys.exit(0)

  if response and 'data' in response:
    data += response['data']

  while 'next_cursor' in response and response['next_cursor'] is not None:
    cursor_url = url + '&cursor=%s' % response['next_cursor']
    res_headers, response = request(user_twurl, http_method, headers, cursor_url)

    if response and 'data' in response:
      data += response['data']

  return data

def gather_stats(user_twurl, headers, account_id, entity_type, start_time, end_time, input_entities, segmentation=None):
  """
    Returns stats data
    Args:
        user_twurl = twurlauth()
        headers = http headers
        account_id = the account of the user/account
        entity_type = type of account
        start_time = start time of stats request
        end_time = ending time of stats request
        input_entities = a list of entities
        http_method = PUT, POST or GET
        segmention = segmentation_type
  """
  entities = list(input_entities)
  resource_url = DOMAIN + "/0/stats/accounts/%s/%s" % (account_id, entity_type)
  query_params = '?granularity=HOUR&start_time=%sZ&end_time=%sZ' % (start_time.isoformat(), end_time.isoformat())
  query_param_entity_name = re.sub(r's$', '_ids', entity_type)
  if segmentation:
    query_params += '&segmentation_type=%s' % segmentation

  query_count = 0
  cost_total = 0
  rate_limited_query_count = 0
  rate_limit_exceeded_sleep_in_sec = 0

  while entities:
    if rate_limit_exceeded_sleep_in_sec > 0:
      print('\t! sleeping for %s' % rate_limit_exceeded_sleep_in_sec)
      time.sleep(rate_limit_exceeded_sleep_in_sec)
      rate_limit_exceeded_sleep_in_sec = 0

    query_entities = []
    limit = 20
    if len(entities) < limit:
      limit = len(entities)

    for _ in range(limit):
      query_entities.append(entities.pop(0))

    stats_url = resource_url + query_params + '&%s=%s' % (query_param_entity_name, ','.join(query_entities))

    res_headers, res_data = request(user_twurl, 'GET', headers, stats_url)

    if 'x-request-cost' in res_headers:
      cost_total += int(res_headers['x-request-cost'])

      if ('x-cost-rate-limit-remaining' in res_headers and
          int(res_headers['x-cost-rate-limit-remaining']) == 0) and res_headers['status'] == '429':
        rate_limit_exceeded_sleep_in_sec = int(res_headers['x-cost-rate-limit-reset']) - int(time.time())

    if res_headers['status'] == '200':
      query_count += 1

      if VERBOSE > 1:
        print('VERBOSE:\tStats Query:\t%s' % stats_url)

    elif res_headers['status'] == '429':
      print("RATE LIMITED! adding entities back to queue")
      rate_limited_query_count += 1
      entities.extend(query_entities)
    elif res_headers['status'] == '503':
      print("TIMEOUT!")
      print(stats_url)
      entities.extend(query_entities)
    else:
      print("ERROR %s" % res_headers['status'])
      print(res_headers)
      sys.exit(0)

  if VERBOSE > 0:
    if segmentation:
      print('VERBOSE:\tSegmentation type:\t%s' % segmentation)
    print('VERBOSE:\tAvg cost per query:\t%s' % str(cost_total / query_count))

  return query_count, cost_total, rate_limited_query_count

def check(data, start_time, end_time, filter_field=None, filter_data=[]):
  """
    Returns a list of ids
    Args:
        data = json format data
        start_time = start time of request
        end_time = end time of request
        filter_filed = filtered fields
  """
  d = []

  if data and len(data) > 0:
    for i in data:
      if 'end_time' in i and i['end_time'] and format_timestamp(i['end_time']) < start_time:
        continue
      elif 'start_time' in i and i['start_time'] and format_timestamp(i['start_time']) > end_time:
        continue
      elif i['deleted'] == True and format_timestamp(i['updated_at']) < start_time:
        continue
      elif i['paused'] == True and format_timestamp(i['updated_at']) < start_time:
        continue
      elif filter_field and i[filter_field] not in filter_data:
        continue
      else:
        d.append(i['id'])

  return d

def format_timestamp(timestamp):
  """
    Returns a string representation of a timestamp to be used by the api
    Args:
        timestamp = datestring
  """
  return datetime.datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ')

def linesep():
  """
    Returns a line seperator
  """
  print('-----------------------------------------------')

if __name__=='__main__':
  options = input()
  main(options)
