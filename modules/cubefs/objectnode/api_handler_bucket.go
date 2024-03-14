// Copyright 2019 The CubeFS Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing
// permissions and limitations under the License.

package objectnode

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util/log"
)

const (
	DefaultMinBucketLength = 3
	DefaultMaxBucketLength = 63
)

var regexBucketName = regexp.MustCompile(`^[0-9a-z][-0-9a-z]+[0-9a-z]$`)

// Head bucket
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html
func (o *ObjectNode) headBucketHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(XAmzBucketRegion, o.region)
}

// Create bucket
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html
func (o *ObjectNode) createBucketHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	if o.disableCreateBucketByS3 {
		errorCode = DisableCreateBucketByS3
		return
	}
	param := ParseRequestParam(r)
	bucket := param.Bucket()
	if bucket == "" {
		errorCode = InvalidBucketName
		return
	}

	if !IsValidBucketName(bucket, DefaultMinBucketLength, DefaultMaxBucketLength) {
		errorCode = InvalidBucketName
		return
	}

	if vol, _ := o.vm.VolumeWithoutBlacklist(bucket); vol != nil {
		log.LogInfof("createBucketHandler: duplicated bucket name: requestID(%v) bucket(%v)", GetRequestID(r), bucket)
		errorCode = BucketAlreadyOwnedByYou
		return
	}

	var userInfo *proto.UserInfo
	if userInfo, err = o.getUserInfoByAccessKeyV2(param.AccessKey()); err != nil {
		log.LogErrorf("createBucketHandler: get user info from master fail: requestID(%v) accessKey(%v) err(%v)",
			GetRequestID(r), param.AccessKey(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(userInfo.UserID, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(userInfo.UserID, param.apiName)

	length, errorCode := VerifyContentLength(r, BodyLimit)
	if errorCode != nil {
		return
	}
	if length > 0 {
		requestBytes, err := io.ReadAll(r.Body)
		if err != nil && err != io.EOF {
			log.LogErrorf("createBucketHandler: read request body fail: requestID(%v) err(%v)", GetRequestID(r), err)
			return
		}
		createBucketRequest := &CreateBucketRequest{}
		err = UnmarshalXMLEntity(requestBytes, createBucketRequest)
		if err != nil {
			log.LogErrorf("createBucketHandler: unmarshal xml fail: requestID(%v) err(%v)",
				GetRequestID(r), err)
			errorCode = InvalidArgument
			return
		}
		if createBucketRequest.LocationConstraint != o.region {
			log.LogErrorf("createBucketHandler: location constraint not match the service: requestID(%v) LocationConstraint(%v) region(%v)",
				GetRequestID(r), createBucketRequest.LocationConstraint, o.region)
			errorCode = InvalidLocationConstraint
			return
		}
	}

	var acl *AccessControlPolicy
	if acl, err = ParseACL(r, userInfo.UserID, false, false); err != nil {
		log.LogErrorf("createBucketHandler: parse acl fail: requestID(%v) err(%v)", GetRequestID(r), err)
		return
	}

	if err = o.mc.AdminAPI().CreateDefaultVolume(bucket, userInfo.UserID); err != nil {
		log.LogErrorf("createBucketHandler: create bucket fail: requestID(%v) volume(%v) accessKey(%v) err(%v)",
			GetRequestID(r), bucket, param.AccessKey(), err)
		return
	}

	w.Header().Set(Location, "/"+bucket)
	w.Header().Set(Connection, "close")

	vol, err1 := o.vm.VolumeWithoutBlacklist(bucket)
	if err1 != nil {
		log.LogWarnf("createBucketHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), bucket, err1)
		return
	}
	if acl != nil {
		if err1 = putBucketACL(vol, acl); err1 != nil {
			log.LogWarnf("createBucketHandler: put acl fail: requestID(%v) volume(%v) acl(%+v) err(%v)",
				GetRequestID(r), bucket, acl, err1)
		}
		vol.metaLoader.storeACL(acl)
	}

	return
}

// Delete bucket
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
func (o *ObjectNode) deleteBucketHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	bucket := param.Bucket()
	if bucket == "" {
		errorCode = InvalidBucketName
		return
	}

	var userInfo *proto.UserInfo
	if userInfo, err = o.getUserInfoByAccessKeyV2(param.AccessKey()); err != nil {
		log.LogErrorf("deleteBucketHandler: get user info fail: requestID(%v) volume(%v) accessKey(%v) err(%v)",
			GetRequestID(r), bucket, param.AccessKey(), err)
		return
	}
	var vol *Volume
	if vol, err = o.getVol(bucket); err != nil {
		log.LogErrorf("deleteBucketHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), bucket, err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	if !vol.IsEmpty() {
		errorCode = BucketNotEmpty
		return
	}

	// delete Volume from master
	var authKey string
	if authKey, err = calculateAuthKey(userInfo.UserID); err != nil {
		log.LogErrorf("deleteBucketHandler: calculate authKey fail: requestID(%v) volume(%v) authKey(%v) err(%v)",
			GetRequestID(r), bucket, userInfo.UserID, err)
		return
	}
	if err = o.mc.AdminAPI().DeleteVolume(bucket, authKey); err != nil {
		log.LogErrorf("deleteBucketHandler: delete volume fail: requestID(%v) volume(%v) accessKey(%v) err(%v)",
			GetRequestID(r), bucket, param.AccessKey(), err)
		return
	}
	log.LogInfof("deleteBucketHandler: delete bucket success: requestID(%v) volume(%v) accessKey(%v)",
		GetRequestID(r), bucket, param.AccessKey())

	// release Volume from Volume manager
	o.vm.Release(bucket)
	w.WriteHeader(http.StatusNoContent)
	return
}

// List buckets
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html
func (o *ObjectNode) listBucketsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	var userInfo *proto.UserInfo
	if userInfo, err = o.getUserInfoByAccessKeyV2(param.accessKey); err != nil {
		log.LogErrorf("listBucketsHandler: get user info fail: requestID(%v) accessKey(%v) err(%v)",
			GetRequestID(r), param.AccessKey(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(userInfo.UserID, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(userInfo.UserID, param.apiName)

	type bucket struct {
		XMLName      xml.Name `xml:"Bucket"`
		CreationDate string   `xml:"CreationDate"`
		Name         string   `xml:"Name"`
	}

	type listBucketsOutput struct {
		XMLName xml.Name `xml:"ListAllMyBucketsResult"`
		Owner   Owner    `xml:"Owner"`
		Buckets []bucket `xml:"Buckets>Bucket"`
	}

	var output listBucketsOutput
	authVos := userInfo.Policy.AuthorizedVols
	ownVols := userInfo.Policy.OwnVols
	for vol := range authVos {
		ownVols = append(ownVols, vol)
	}
	for _, ownVol := range ownVols {
		var vol *Volume
		if vol, err = o.getVol(ownVol); err != nil {
			log.LogErrorf("listBucketsHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
				GetRequestID(r), ownVol, err)
			continue
		}
		output.Buckets = append(output.Buckets, bucket{
			Name:         ownVol,
			CreationDate: formatTimeISO(vol.CreateTime()),
		})
	}
	output.Owner = Owner{DisplayName: userInfo.UserID, Id: userInfo.UserID}

	response, err := MarshalXMLEntity(&output)
	if err != nil {
		log.LogErrorf("listBucketsHandler: xml marshal result fail: requestID(%v) result(%v) err(%v)",
			GetRequestID(r), output, err)
		return
	}

	writeSuccessResponseXML(w, response)
	return
}

// Get bucket location
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketLocation.html
func (o *ObjectNode) getBucketLocationHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	var vol *Volume
	param := ParseRequestParam(r)
	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("getBucketLocationHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	location := LocationResponse{Location: o.region}
	response, err := MarshalXMLEntity(location)
	if err != nil {
		log.LogErrorf("getBucketLocationHandler: xml marshal fail: requestID(%v) location(%v) err(%v)",
			GetRequestID(r), location, err)
		return
	}

	writeSuccessResponseXML(w, response)
	return
}

// Get bucket tagging
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketTagging.html
func (o *ObjectNode) getBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	if len(param.Bucket()) == 0 {
		errorCode = InvalidBucketName
		return
	}
	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("getBucketTaggingHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	var xattrInfo *proto.XAttrInfo
	if xattrInfo, err = vol.GetXAttr(bucketRootPath, XAttrKeyOSSTagging); err != nil {
		log.LogErrorf("getBucketTaggingHandler: Volume get XAttr fail: requestID(%v) err(%v)", GetRequestID(r), err)
		return
	}
	ossTaggingData := xattrInfo.Get(XAttrKeyOSSTagging)
	output, _ := ParseTagging(string(ossTaggingData))
	if nil == output || len(output.TagSet) == 0 {
		errorCode = NoSuchTagSetError
		return
	}

	response, err := MarshalXMLEntity(output)
	if err != nil {
		log.LogErrorf("getBucketTaggingHandler: xml marshal result fail: requestID(%v) result(%v) err(%v)",
			GetRequestID(r), output, err)
		return
	}

	writeSuccessResponseXML(w, response)
	return
}

// Put bucket tagging
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketTagging.html
func (o *ObjectNode) putBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("putBucketTaggingHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	_, errorCode = VerifyContentLength(r, BodyLimit)
	if errorCode != nil {
		return
	}
	var body []byte
	if body, err = io.ReadAll(r.Body); err != nil {
		log.LogErrorf("putBucketTaggingHandler: read request body data fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		errorCode = InvalidArgument
		return
	}

	tagging := NewTagging()
	if err = UnmarshalXMLEntity(body, tagging); err != nil {
		log.LogWarnf("putBucketTaggingHandler: unmarshal request body fail: requestID(%v) body(%v) err(%v)",
			GetRequestID(r), string(body), err)
		errorCode = InvalidArgument
		return
	}
	if err = tagging.Validate(); err != nil {
		log.LogErrorf("putBucketTaggingHandler: tagging validate fail: requestID(%v) tagging(%v) err(%v)",
			GetRequestID(r), tagging, err)
		return
	}

	err = vol.SetXAttr(bucketRootPath, XAttrKeyOSSTagging, []byte(tagging.Encode()), false)
	if err != nil {
		log.LogErrorf("putBucketTaggingHandler: set tagging xattr fail: requestID(%v) tagging(%v) err(%v)",
			GetRequestID(r), tagging.Encode(), err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	return
}

// Delete bucket tagging
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketTagging.html
func (o *ObjectNode) deleteBucketTaggingHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	if len(param.Bucket()) == 0 {
		errorCode = InvalidBucketName
		return
	}
	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("deleteBucketTaggingHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	if err = vol.DeleteXAttr(bucketRootPath, XAttrKeyOSSTagging); err != nil {
		log.LogErrorf("deleteBucketTaggingHandler: delete tagging xattr fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	return
}

func calculateAuthKey(key string) (authKey string, err error) {
	h := md5.New()
	_, err = h.Write([]byte(key))
	if err != nil {
		log.LogErrorf("calculateAuthKey: calculate auth key fail: key[%v] err[%v]", key, err)
		return
	}
	cipherStr := h.Sum(nil)
	return strings.ToLower(hex.EncodeToString(cipherStr)), nil
}

func (o *ObjectNode) getUserInfoByAccessKey(accessKey string) (userInfo *proto.UserInfo, err error) {
	userInfo, err = o.userStore.LoadUser(accessKey)
	return
}

// Put Object Lock Configuration
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectLockConfiguration.html
func (o *ObjectNode) putObjectLockConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("putObjectLockConfigurationHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}
	var body []byte
	if body, err = io.ReadAll(io.LimitReader(r.Body, MaxObjectLockSize+1)); err != nil {
		log.LogErrorf("putObjectLockConfigurationHandler: read request body fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), vol.Name(), err)
		return
	}
	if len(body) > MaxObjectLockSize {
		errorCode = EntityTooLarge
		return
	}
	var config *ObjectLockConfig
	if config, err = ParseObjectLockConfigFromXML(body); err != nil {
		log.LogErrorf("putObjectLockConfigurationHandler: parse object lock config fail: requestID(%v) volume(%v) config(%v) err(%v)",
			GetRequestID(r), vol.Name(), string(body), err)
		return
	}
	if body, err = json.Marshal(config); err != nil {
		log.LogErrorf("putObjectLockConfigurationHandler: json.Marshal object lock config fail: requestID(%v) volume(%v) config(%v) err(%v)",
			GetRequestID(r), vol.Name(), config, err)
		return
	}
	if err = storeObjectLock(body, vol); err != nil {
		log.LogErrorf("putObjectLockConfigurationHandler: store object lock config fail: requestID(%v) volume(%v) config(%v) err(%v)",
			GetRequestID(r), vol.Name(), string(body), err)
		return
	}
	vol.metaLoader.storeObjectLock(config)

	w.WriteHeader(http.StatusNoContent)
	return
}

// Get Object Lock Configuration
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html
func (o *ObjectNode) getObjectLockConfigurationHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}

	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("getObjectLockConfigurationHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	var config *ObjectLockConfig
	if config, err = vol.metaLoader.loadObjectLock(); err != nil {
		log.LogErrorf("getObjectLockConfigurationHandler: load object lock fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), vol.Name(), err)
		return
	}
	if config == nil || config.IsEmpty() {
		errorCode = ObjectLockConfigurationNotFound
		return
	}
	var data []byte
	if data, err = MarshalXMLEntity(config); err != nil {
		log.LogErrorf("getObjectLockConfigurationHandler: xml marshal fail: requestID(%v) volume(%v) cors(%+v) err(%v)",
			GetRequestID(r), vol.Name(), config, err)
		return
	}

	writeSuccessResponseXML(w, data)
	return
}

func (o *ObjectNode) getUserInfoByAccessKeyV2(accessKey string) (userInfo *proto.UserInfo, err error) {
	userInfo, err = o.userStore.LoadUser(accessKey)
	if err == proto.ErrUserNotExists || err == proto.ErrAccessKeyNotExists || err == proto.ErrParamError {
		err = InvalidAccessKeyId
	}
	return
}

func IsValidBucketName(bucketName string, minBucketLength, maxBucketLength int) bool {
	if len(bucketName) < minBucketLength || len(bucketName) > maxBucketLength {
		return false
	}
	if !regexBucketName.MatchString(bucketName) {
		return false
	}
	return true
}
