import asyncForEach from '../lib/asyncForEach';

// eslint-disable-next-line import/no-extraneous-dependencies
const AWS = require('aws-sdk');

const db = new AWS.DynamoDB.DocumentClient({ region: process.env.AWS_REGION });

const dbClient = {
  async get(id, sortKey) {
    return db
      .get({
        TableName: process.env.DYNAMODB_TABLE,
        Key: { id, sortKey },
      })
      .promise()
      .then((response) => response.Item);
  },
  // startTime: 20210805144159
  // endTime: 20210805144159
  async list(
    id,
    sortKeyPrefix,
    { limit, limitStartKey, startTime, endTime, query, filterString } = {}
  ) {
    let KeyConditionExpression = 'id = :id';
    let ExpressionAttributeValues = {
      ':id': id,
    };

    if (sortKeyPrefix && startTime && endTime) {
      KeyConditionExpression =
        'id = :id and sortKey between :startTime and :endTime';
      ExpressionAttributeValues = {
        ':id': id,
        ':startTime': `${sortKeyPrefix}${startTime}`,
        ':endTime': `${sortKeyPrefix}${endTime}`,
      };
    } else if (sortKeyPrefix) {
      KeyConditionExpression =
        'id = :id and begins_with(sortKey, :sortKeyPrefix)';
      ExpressionAttributeValues = {
        ':id': id,
        ':sortKeyPrefix': sortKeyPrefix,
      };
    }

    const params = {
      TableName: process.env.DYNAMODB_TABLE,
      KeyConditionExpression,
      ExpressionAttributeValues,
      ScanIndexForward: false,
    };
    if (query && filterString) {
      const queryExpression = {};
      Object.keys(query).forEach((key) => {
        queryExpression[`:${key}`] = query[key];
      });
      const attributeNames = {};
      Object.keys(query).forEach((key) => {
        attributeNames[`#${key}`] = key;
      });

      params.ExpressionAttributeValues = {
        ...params.ExpressionAttributeValues,
        ...queryExpression,
      };
      params.ExpressionAttributeNames = attributeNames;
      params.FilterExpression = filterString;
    }

    if (limit) {
      params.Limit = limit;
      params.ExclusiveStartKey = limitStartKey;
    }

    const response = await db.query(params).promise();

    return {
      items: response.Items,
      lastEvaluatedKey: response.LastEvaluatedKey,
    };
  },
  async create(item) {
    const updatedItem = { ...item, createdAt: item.createdAt || Date.now() };
    const params = {
      TableName: process.env.DYNAMODB_TABLE,
      Item: updatedItem,
    };

    await db.put(params).promise();

    return updatedItem;
  },
  async update(id, sortKey, item) {
    const current = await dbClient.get(id, sortKey);
    const updatedItem = {
      ...(current || {}),
      ...item,
      id,
      sortKey,
      updatedAt: Date.now(),
    };

    return dbClient.create(updatedItem);
  },
  async delete(id, sortKey) {
    const params = {
      TableName: process.env.DYNAMODB_TABLE,
      Key: { id, sortKey },
    };

    return db
      .delete(params)
      .promise()
      .then(() => ({ id, sortKey }));
  },
  async deleteWithPrefix(id, sortKeyPrefix) {
    const { items } = await dbClient.list(id, sortKeyPrefix);
    if (items && items.length) {
      await asyncForEach(items, async (item) => {
        await dbClient.delete(id, item.sortKey);
      });
    }
  },
};

export default dbClient;
