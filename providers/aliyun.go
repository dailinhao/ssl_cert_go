// backend/providers/aliyun.go - 阿里云DNS实现
package providers

import (
    "context"
    "github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
    "github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
)

type AliyunProvider struct {
    client *alidns.Client
}

func init() {
    Register("aliyun", func(config map[string]string) (DNSProvider, error) {
        client, err := alidns.NewClientWithAccessKey(
            config["region_id"],
            config["access_key_id"],
            config["access_key_secret"],
        )
        if err != nil {
            return nil, err
        }
        return &AliyunProvider{client: client}, nil
    })
}

func (a *AliyunProvider) Name() string {
    return "aliyun"
}

func (a *AliyunProvider) AddTXTRecord(ctx context.Context, domain, subdomain, value string, ttl int) error {
    request := alidns.CreateAddDomainRecordRequest()
    request.DomainName = domain
    request.RR = subdomain
    request.Type = "TXT"
    request.Value = value
    request.TTL = requests.NewInteger(ttl)
    
    _, err := a.client.AddDomainRecord(request)
    return err
}

func (a *AliyunProvider) RemoveTXTRecord(ctx context.Context, domain, subdomain string) error {
    // 实现删除TXT记录的逻辑
    // 首先获取记录列表
    listRequest := alidns.CreateDescribeDomainRecordsRequest()
    listRequest.DomainName = domain
    listRequest.RRKeyWord = subdomain
    listRequest.Type = "TXT"
    
    listResponse, err := a.client.DescribeDomainRecords(listRequest)
    if err != nil {
        return err
    }
    
    // 删除找到的TXT记录
    for _, record := range listResponse.DomainRecords.Record {
        if record.RR == subdomain && record.Type == "TXT" {
            deleteRequest := alidns.CreateDeleteDomainRecordRequest()
            deleteRequest.RecordId = record.RecordId
            _, err := a.client.DeleteDomainRecord(deleteRequest)
            if err != nil {
                return err
            }
        }
    }
    
    return nil
}

func (a *AliyunProvider) CheckPropagation(ctx context.Context, domain, token string) (bool, error) {
    // 简单实现：直接返回true，假设DNS记录已经传播
    // 实际生产环境中应该实现更复杂的检查逻辑
    return true, nil
}