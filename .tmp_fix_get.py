# -*- coding: utf-8 -*-
"""Fix the duplicated strategyId path: fold GET into the existing block."""
import io

NL = chr(10)
p = 'openapi.yaml'
s = io.open(p, encoding='utf-8').read()

key = '  /api/v1/orgs/{orgId}/strategies/{strategyId}:' + NL
idx_first = s.index(key)
idx_second = s.index(key, idx_first + 1)

# The erroneous insertion runs from the second key up to the start of the
# original block (i.e. the text before the first key).
bad = s[idx_second:idx_first]
assert bad.lstrip().startswith('/api') is False
s = s[:idx_second] + s[idx_first:]

# Now there is exactly one path key; insert the get operation inside it.
assert s.count(key) == 1, s.count(key)
get_op = '''  /api/v1/orgs/{orgId}/strategies/{strategyId}:
    get:
      operationId: getStrategy
      summary: 读取单个客户端策略
      description: |
        返回一个策略的完整定义（含 `version` 与已清除的键）。任何组织成员可读；
        跨组织 id 与不存在都返回 404。
      tags:
        - orgs
      security:
        - bearerAuth: []
      parameters:
        - name: orgId
          in: path
          required: true
          schema:
            type: integer
            format: int64
        - name: strategyId
          in: path
          required: true
          schema:
            type: integer
            format: int64
      responses:
        "200":
          description: 策略
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/StrategyResponse"
        "401":
          $ref: "#/components/responses/Unauthorized"
        "403":
          $ref: "#/components/responses/Forbidden"
        "404":
          $ref: "#/components/responses/NotFound"
'''
s = s.replace(key, get_op, 1)

io.open(p, 'w', encoding='utf-8', newline=NL).write(s)
print('path fixed, occurrences:', s.count('  /api/v1/orgs/{orgId}/strategies/{strategyId}:') if False else 'ok')
