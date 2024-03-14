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
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cubefs/cubefs/blobstore/common/trace"
	"github.com/cubefs/cubefs/proto"
	"github.com/cubefs/cubefs/util/log"
)

var (
	MinPartNumberValid        = 1
	MaxPartNumberValid        = 10000
	MinPartSizeBytes   uint64 = 1024 * 1024
	MaxPartCopySize    int64  = 5 << 30 // 5GBytes
)

// Create multipart upload
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateMultipartUpload.html
func (o *ObjectNode) createMultipleUploadHandler(w http.ResponseWriter, r *http.Request) {
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
	if param.Object() == "" {
		errorCode = InvalidKey
		return
	}
	if len(param.Object()) > MaxKeyLength {
		errorCode = KeyTooLong
		return
	}
	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("createMultipleUploadHandler: load volume fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	var userInfo *proto.UserInfo
	if userInfo, err = o.getUserInfoByAccessKeyV2(param.AccessKey()); err != nil {
		log.LogErrorf("createMultipleUploadHandler: get user info fail: requestID(%v) accessKey(%v) err(%v)",
			GetRequestID(r), param.AccessKey(), err)
		return
	}

	// metadata
	contentType := r.Header.Get(ContentType)
	contentDisposition := r.Header.Get(ContentDisposition)
	cacheControl := r.Header.Get(CacheControl)
	if len(cacheControl) > 0 && !ValidateCacheControl(cacheControl) {
		errorCode = InvalidCacheArgument
		return
	}
	expires := r.Header.Get(Expires)
	if len(expires) > 0 && !ValidateCacheExpires(expires) {
		errorCode = InvalidCacheArgument
		return
	}

	// Checking user-defined metadata
	metadata := ParseUserDefinedMetadata(r.Header)

	// Check 'x-amz-tagging' header
	var tagging *Tagging
	if xAmxTagging := r.Header.Get(XAmzTagging); xAmxTagging != "" {
		if tagging, err = ParseTagging(xAmxTagging); err != nil {
			errorCode = InvalidArgument
			return
		}
	}
	// Check ACL
	var acl *AccessControlPolicy
	acl, err = ParseACL(r, userInfo.UserID, false, vol.GetOwner() != userInfo.UserID)
	if err != nil {
		log.LogErrorf("createMultipleUploadHandler: parse acl fail: requestID(%v) acl(%+v) err(%v)",
			GetRequestID(r), acl, err)
		return
	}
	opt := &PutFileOption{
		MIMEType:     contentType,
		Disposition:  contentDisposition,
		Tagging:      tagging,
		Metadata:     metadata,
		CacheControl: cacheControl,
		Expires:      expires,
		ACL:          acl,
	}

	var uploadID string
	if uploadID, err = vol.InitMultipart(param.Object(), opt); err != nil {
		log.LogErrorf("createMultipleUploadHandler: init multipart fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	initResult := InitMultipartResult{
		Bucket:   param.Bucket(),
		Key:      param.Object(),
		UploadId: uploadID,
	}
	response, err := MarshalXMLEntity(initResult)
	if err != nil {
		log.LogErrorf("createMultipleUploadHandler: xml marshal result fail: requestID(%v) result(%v) err(%v)",
			GetRequestID(r), initResult, err)
		return
	}

	writeSuccessResponseXML(w, response)
	return
}

// Upload part
// Uploads a part in a multipart upload.
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPart.html .
func (o *ObjectNode) uploadPartHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)

	span := trace.SpanFromContextSafe(r.Context())
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	// check args
	param := ParseRequestParam(r)
	// get upload id and part number
	uploadId := param.GetVar(ParamUploadId)
	partNumber := param.GetVar(ParamPartNumber)
	if uploadId == "" || partNumber == "" {
		log.LogErrorf("uploadPartHandler: illegal uploadID or partNumber, requestID(%v)", GetRequestID(r))
		errorCode = InvalidArgument
		return
	}

	var partNumberInt uint16
	if partNumberInt, err = safeConvertStrToUint16(partNumber); err != nil {
		log.LogErrorf("uploadPartHandler: parse part number fail, requestID(%v) raw(%v) err(%v)",
			GetRequestID(r), partNumber, err)
		errorCode = InvalidPartNumber
		return
	}
	if partNumberInt < uint16(MinPartNumberValid) || partNumberInt > uint16(MaxPartNumberValid) {
		errorCode = InvalidPartNumber
		return
	}

	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	if param.Object() == "" {
		errorCode = InvalidKey
		return
	}

	// Get request MD5, if request MD5 is not empty, compute and verify it.
	requestMD5 := r.Header.Get(ContentMD5)
	if requestMD5 != "" {
		decoded, err := base64.StdEncoding.DecodeString(requestMD5)
		if err != nil {
			errorCode = InvalidDigest
			return
		}
		requestMD5 = hex.EncodeToString(decoded)
	}

	// Verify ContentLength
	length := GetContentLength(r)
	if length > SinglePutLimit {
		errorCode = EntityTooLarge
		return
	}
	if length < 0 {
		errorCode = MissingContentLength
		return
	}

	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("uploadPartHandler: load volume fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	// ObjectLock  Config
	objetLock, err := vol.metaLoader.loadObjectLock()
	if err != nil {
		log.LogErrorf("putObjectHandler: load volume objetLock: requestID(%v)  volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}
	if objetLock != nil && objetLock.ToRetention() != nil && requestMD5 == "" {
		errorCode = NoContentMd5HeaderErr
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	// Flow Control
	var reader io.Reader
	if length > DefaultFlowLimitSize {
		reader = rateLimit.GetReader(vol.owner, param.apiName, r.Body)
	} else {
		reader = r.Body
	}

	// Write Part
	start := time.Now()
	fsFileInfo, err := vol.WritePart(param.Object(), uploadId, partNumberInt, reader)
	span.AppendTrackLog("part.w", start, err)
	if err != nil {
		log.LogErrorf("uploadPartHandler: write part fail: requestID(%v) volume(%v) path(%v) uploadId(%v) part(%v) err(%v)",
			GetRequestID(r), vol.Name(), param.Object(), uploadId, partNumberInt, err)
		err = handleWritePartErr(err)
		return
	}

	// check content MD5
	if requestMD5 != "" && requestMD5 != fsFileInfo.ETag {
		log.LogErrorf("uploadPartHandler: MD5 validate fail: requestID(%v) volume(%v) path(%v) requestMD5(%v) serverMD5(%v)",
			GetRequestID(r), vol.Name(), param.Object(), requestMD5, fsFileInfo.ETag)
		errorCode = BadDigest
		return
	}

	// write header to response
	w.Header()[ETag] = []string{"\"" + fsFileInfo.ETag + "\""}
	return
}

// Upload part copy
// Uploads a part in a multipart upload by copying a existed object.
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_UploadPartCopy.html .
func (o *ObjectNode) uploadPartCopyHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)

	span := trace.SpanFromContextSafe(r.Context())
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	// step1: check args
	param := ParseRequestParam(r)
	uploadId := param.GetVar(ParamUploadId)
	partNumber := param.GetVar(ParamPartNumber)
	if uploadId == "" || partNumber == "" {
		log.LogErrorf("uploadPartCopyHandler: illegal uploadID or partNumber, requestID(%v)", GetRequestID(r))
		errorCode = InvalidArgument
		return
	}
	var partNumberInt uint16
	if partNumberInt, err = safeConvertStrToUint16(partNumber); err != nil {
		log.LogErrorf("uploadPartCopyHandler: parse part number fail, requestID(%v) raw(%v) err(%v)",
			GetRequestID(r), partNumber, err)
		errorCode = InvalidPartNumber
		return
	}
	if partNumberInt < uint16(MinPartNumberValid) || partNumberInt > uint16(MaxPartNumberValid) {
		errorCode = InvalidPartNumber
		return
	}

	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	if param.Object() == "" {
		errorCode = InvalidKey
		return
	}
	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("uploadPartCopyHandler: load volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	// step2: extract params from req
	srcBucket, srcObject, _, err := extractSrcBucketKey(r)
	if err != nil {
		log.LogDebugf("uploadPartCopyHandler: copySource(%v) argument invalid: requestID(%v)",
			r.Header.Get(XAmzCopySource), GetRequestID(r))
		return
	}

	// step3: get srcObject metadata
	var srcVol *Volume
	if srcVol, err = o.getVol(srcBucket); err != nil {
		log.LogErrorf("uploadPartCopyHandler: load src volume fail: requestID(%v) volume(%v) err(%v)",
			GetRequestID(r), srcBucket, err)
		return
	}
	start := time.Now()
	srcFileInfo, _, err := srcVol.ObjectMeta(srcObject)
	span.AppendTrackLog("meta.r", start, err)
	if err != nil {
		log.LogErrorf("uploadPartCopyHandler: get fileMeta fail: requestId(%v) srcVol(%v) path(%v) err(%v)",
			GetRequestID(r), srcBucket, srcObject, err)
		if err == syscall.ENOENT {
			errorCode = NoSuchKey
		}
		return
	}

	errorCode = CheckConditionInHeader(r, srcFileInfo)
	if errorCode != nil {
		return
	}

	// step4: extract range params
	copyRange := r.Header.Get(XAmzCopySourceRange)
	firstByte, copyLength, errorCode := determineCopyRange(copyRange, srcFileInfo.Size)
	if errorCode != nil {
		return
	}
	size, err := safeConvertInt64ToUint64(srcFileInfo.Size)
	if err != nil {
		return
	}
	fb, err := safeConvertInt64ToUint64(firstByte)
	if err != nil {
		return
	}
	cl, err := safeConvertInt64ToUint64(copyLength)
	if err != nil {
		return
	}
	reader, writer := io.Pipe()
	go func() {
		err = srcVol.readFile(srcFileInfo.Inode, size, srcObject, writer, fb, cl)
		if err != nil {
			log.LogErrorf("uploadPartCopyHandler: read srcObj err(%v): requestId(%v) srcVol(%v) path(%v)",
				err, GetRequestID(r), srcBucket, srcObject)
		}
		writer.CloseWithError(err)
	}()

	// step5: upload part by copy and flow control
	var rd io.Reader
	if copyLength > DefaultFlowLimitSize {
		rd = rateLimit.GetReader(vol.owner, param.apiName, reader)
	} else {
		rd = reader
	}
	start = time.Now()
	fsFileInfo, err := vol.WritePart(param.Object(), uploadId, partNumberInt, rd)
	span.AppendTrackLog("part.w", start, err)
	if err != nil {
		log.LogErrorf("uploadPartCopyHandler: write part fail: requestID(%v) volume(%v) path(%v) uploadId(%v) part(%v) err(%v)",
			GetRequestID(r), vol.Name(), param.Object(), uploadId, partNumberInt, err)
		if err == syscall.ENOENT {
			errorCode = NoSuchUpload
			return
		}
		if err == syscall.EAGAIN {
			errorCode = ConflictUploadRequest
			return
		}
		if err == io.ErrUnexpectedEOF {
			errorCode = EntityTooSmall
		}
		return
	}

	Etag := "\"" + fsFileInfo.ETag + "\""
	w.Header()[ETag] = []string{Etag}
	response := NewS3CopyPartResult(Etag, fsFileInfo.CreateTime.UTC().Format(time.RFC3339)).String()

	writeSuccessResponseXML(w, []byte(response))
	return
}

func handleWritePartErr(err error) error {
	if err == syscall.ENOENT {
		return NoSuchUpload
	}
	if err == syscall.EEXIST {
		return ConflictUploadRequest
	}
	if err == io.ErrUnexpectedEOF {
		return EntityTooSmall
	}
	return err
}

// List parts
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListParts.html
func (o *ObjectNode) listPartsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)

	span := trace.SpanFromContextSafe(r.Context())
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	// get upload id and part number
	uploadId := param.GetVar(ParamUploadId)
	maxParts := param.GetVar(ParamMaxParts)
	partNoMarker := param.GetVar(ParamPartNoMarker)

	var maxPartsInt uint64
	var partNoMarkerInt uint64

	if uploadId == "" {
		log.LogErrorf("listPartsHandler: illegal update ID, requestID(%v) err(%v)", GetRequestID(r), err)
		errorCode = InvalidArgument
		return
	}

	if maxParts == "" {
		maxPartsInt = MaxParts
	} else {
		maxPartsInt, err = strconv.ParseUint(maxParts, 10, 64)
		if err != nil {
			log.LogErrorf("listPartsHandler: parse max parts fail: requestID(%v) raw(%v) err(%v)",
				GetRequestID(r), maxParts, err)
			errorCode = InvalidArgument
			return
		}
		if maxPartsInt > MaxParts {
			maxPartsInt = MaxParts
		}
	}
	if partNoMarker != "" {
		res, err := strconv.ParseUint(partNoMarker, 10, 64)
		if err != nil {
			log.LogErrorf("listPatsHandler: parse part number marker fail: requestID(%v) raw(%v) err(%v)",
				GetRequestID(r), partNoMarker, err)
			errorCode = InvalidArgument
			return
		}
		partNoMarkerInt = res
	}

	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	if param.Object() == "" {
		errorCode = InvalidKey
		return
	}

	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("listPartsHandler: load volume fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	// List Parts
	start := time.Now()
	fsParts, nextMarker, isTruncated, err := vol.ListParts(param.Object(), uploadId, maxPartsInt, partNoMarkerInt)
	span.AppendTrackLog("part.l", start, err)
	if err != nil {
		log.LogErrorf("listPartsHandler: list parts fail, requestID(%v) uploadID(%v) maxParts(%v) partNoMarker(%v) err(%v)",
			GetRequestID(r), uploadId, maxPartsInt, partNoMarkerInt, err)
		if err == syscall.ENOENT {
			errorCode = NoSuchUpload
		}
		return
	}

	// get owner
	bucketOwner := NewBucketOwner(vol)
	initiator := NewInitiator(vol)

	// get parts
	parts := NewParts(fsParts)

	listPartsResult := ListPartsResult{
		Bucket:       param.Bucket(),
		Key:          param.Object(),
		UploadId:     uploadId,
		StorageClass: StorageClassStandard,
		NextMarker:   nextMarker,
		MaxParts:     maxPartsInt,
		IsTruncated:  isTruncated,
		Parts:        parts,
		Owner:        bucketOwner,
		Initiator:    initiator,
	}
	response, err := MarshalXMLEntity(listPartsResult)
	if err != nil {
		log.LogErrorf("listPartsHandler: xml marshal result fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	writeSuccessResponseXML(w, response)
	return
}

func (o *ObjectNode) checkReqParts(param *RequestParam, reqParts *CompleteMultipartUploadRequest, multipartInfo *proto.MultipartInfo) (
	discardedPartInodes map[uint64]uint16, committedPartInfo *proto.MultipartInfo, err error) {
	if len(reqParts.Parts) <= 0 {
		err = InvalidPart
		log.LogErrorf("checkReqParts: upload part is empty: requestID(%v) volume(%v)", GetRequestID(param.r), param.Bucket())
		return
	}

	reqInfo := make(map[int]int, 0)
	for _, reqPart := range reqParts.Parts {
		reqInfo[reqPart.PartNumber] = 0
	}

	committedPartInfo = &proto.MultipartInfo{
		ID:       multipartInfo.ID,
		Path:     multipartInfo.Path,
		InitTime: multipartInfo.InitTime,
		Parts:    make([]*proto.MultipartPartInfo, 0),
		Extend:   make(map[string]string),
	}
	for key, val := range multipartInfo.Extend {
		committedPartInfo.Extend[key] = val
	}

	saveParts := multipartInfo.Parts
	sort.SliceStable(saveParts, func(i, j int) bool { return saveParts[i].ID < saveParts[j].ID })

	maxPartNum := saveParts[len(saveParts)-1].ID
	allSaveParts := make([]*proto.MultipartPartInfo, maxPartNum+1)
	uploadedInfo := make(map[uint16]string, 0)
	discardedPartInodes = make(map[uint64]uint16, 0)
	for _, uploadedPart := range multipartInfo.Parts {
		log.LogDebugf("checkReqParts: server save part check: requestID(%v) volume(%v) part(%v)",
			GetRequestID(param.r), param.Bucket(), uploadedPart)
		eTag := uploadedPart.MD5
		if strings.Contains(eTag, "\"") {
			eTag = strings.ReplaceAll(eTag, "\"", "")
		}
		uploadedInfo[uploadedPart.ID] = eTag
		if _, existed := reqInfo[int(uploadedPart.ID)]; !existed {
			discardedPartInodes[uploadedPart.Inode] = uploadedPart.ID
		} else {
			committedPartInfo.Parts = append(committedPartInfo.Parts, uploadedPart)
		}
		allSaveParts[uploadedPart.ID] = uploadedPart
	}

	for idx, reqPart := range reqParts.Parts {
		if reqPart.PartNumber >= len(allSaveParts) {
			err = InvalidPart
			return
		}
		if allSaveParts[reqPart.PartNumber].Size < MinPartSizeBytes && idx < len(reqParts.Parts)-1 {
			err = EntityTooSmall
			return
		}
		if eTag, existed := uploadedInfo[uint16(reqPart.PartNumber)]; !existed {
			log.LogErrorf("checkReqParts: request part not existed: requestID(%v) volume(%v) part(%v)",
				GetRequestID(param.r), param.Bucket(), reqPart)
			err = InvalidPart
			return
		} else {
			reqEtag := reqPart.ETag
			if strings.Contains(reqEtag, "\"") {
				reqEtag = strings.ReplaceAll(reqEtag, "\"", "")
			}
			if eTag != reqEtag {
				log.LogErrorf("checkReqParts: part(%v) md5 not matched: requestID(%v) volume(%v) reqETag(%v) eTag(%v)",
					reqPart.PartNumber, GetRequestID(param.r), param.Bucket(), reqEtag, eTag)
				err = InvalidPart
				return
			}
		}
	}
	return
}

// Complete multipart
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_CompleteMultipartUpload.html
func (o *ObjectNode) completeMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)

	span := trace.SpanFromContextSafe(r.Context())
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	// get upload id and part number
	uploadId := param.GetVar(ParamUploadId)
	if uploadId == "" {
		log.LogErrorf("completeMultipartUploadHandler: non upload ID specified: requestID(%v)", GetRequestID(r))
		errorCode = InvalidArgument
		return
	}

	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	if param.Object() == "" {
		errorCode = InvalidKey
		return
	}
	if len(param.Object()) > MaxKeyLength {
		errorCode = KeyTooLong
		return
	}

	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("completeMultipartUploadHandler: load volume fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	// get uploaded part info in request
	_, errorCode = VerifyContentLength(r, BodyLimit)
	if errorCode != nil {
		return
	}
	requestBytes, err := io.ReadAll(r.Body)
	if err != nil && err != io.EOF {
		log.LogErrorf("completeMultipartUploadHandler: read request body fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}
	multipartUploadRequest := &CompleteMultipartUploadRequest{}
	err = UnmarshalXMLEntity(requestBytes, multipartUploadRequest)
	if err != nil {
		log.LogErrorf("completeMultipartUploadHandler: unmarshal xml fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		errorCode = MalformedXML
		return
	}
	// check part parameter
	partsLen := len(multipartUploadRequest.Parts)
	if partsLen > MaxPartNumberValid {
		errorCode = InvalidMaxPartNumber
		return
	}
	if partsLen < MinPartNumberValid {
		errorCode = InvalidMinPartNumber
		return
	}
	previousPartNum := 0
	for _, p := range multipartUploadRequest.Parts {
		if p.PartNumber < MinPartNumberValid || p.PartNumber > MaxPartNumberValid {
			log.LogErrorf("completeMultipartUploadHandler: invalid part number: requestID(%v) partNum=%d",
				GetRequestID(r), p.PartNumber)
			errorCode = InvalidPartNumber
			return
		}
		if p.PartNumber < previousPartNum {
			log.LogErrorf("completeMultipartUploadHandler: invalid part order: requestID(%v) prevPartNum=%d partNum=%d",
				GetRequestID(r), previousPartNum, p.PartNumber)
			errorCode = InvalidPartOrder
			return
		}
		previousPartNum = p.PartNumber
		etag := strings.ReplaceAll(p.ETag, "\"", "")
		if etag == "" {
			errorCode = InvalidPart
			return
		}
	}

	// get multipart info
	start := time.Now()
	multipartInfo, err := vol.mw.GetMultipart_ll(param.object, uploadId)
	span.AppendTrackLog("part.r", start, err)
	if err != nil {
		log.LogErrorf("completeMultipartUploadHandler: meta get multipart fail: requestID(%v) path(%v) err(%v)",
			GetRequestID(r), param.object, err)
		if err == syscall.ENOENT {
			errorCode = NoSuchUpload
			return
		}
		if err == syscall.EINVAL {
			errorCode = ObjectModeConflict
		}
		return
	}

	discardedInods, committedPartInfo, err := o.checkReqParts(param, multipartUploadRequest, multipartInfo)
	if err != nil {
		log.LogWarnf("completeMultipartUploadHandler: check request parts fail: requestID(%v) path(%v) err(%v)",
			GetRequestID(r), param.object, errorCode)
		return
	}

	// complete multipart
	start = time.Now()
	fsFileInfo, err := vol.CompleteMultipart(param.Object(), uploadId, committedPartInfo, discardedInods)
	span.AppendTrackLog("part.c", start, err)
	if err != nil {
		log.LogErrorf("completeMultipartUploadHandler: complete multipart fail: requestID(%v) volume(%v) uploadID(%v) err(%v)",
			GetRequestID(r), param.Bucket(), uploadId, err)
		if err == syscall.EINVAL {
			errorCode = ObjectModeConflict
		}
		return
	}

	completeResult := CompleteMultipartResult{
		Bucket: param.Bucket(),
		Key:    param.Object(),
		ETag:   wrapUnescapedQuot(fsFileInfo.ETag),
	}
	response, ierr := MarshalXMLEntity(completeResult)
	if ierr != nil {
		log.LogErrorf("completeMultipartUploadHandler: xml marshal result fail: requestID(%v) result(%v) err(%v)",
			GetRequestID(r), completeResult, ierr)
	}

	writeSuccessResponseXML(w, response)
	return
}

// Abort multipart
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html .
func (o *ObjectNode) abortMultipartUploadHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	// check args
	param := ParseRequestParam(r)
	uploadId := param.GetVar(ParamUploadId)
	if uploadId == "" {
		errorCode = InvalidArgument
		return
	}
	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}
	if param.Object() == "" {
		errorCode = InvalidKey
		return
	}

	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("abortMultipartUploadHandler: load volume fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	// Abort multipart upload
	if err = vol.AbortMultipart(param.Object(), uploadId); err != nil {
		log.LogErrorf("abortMultipartUploadHandler: abort multipart fail: requestID(%v) uploadID(%v) err(%v)",
			GetRequestID(r), uploadId, err)
		if err == syscall.ENOENT {
			errorCode = NoSuchUpload
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
	return
}

// List multipart uploads
// API reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListMultipartUploads.html
func (o *ObjectNode) listMultipartUploadsHandler(w http.ResponseWriter, r *http.Request) {
	var (
		err       error
		errorCode *ErrorCode
	)

	span := trace.SpanFromContextSafe(r.Context())
	defer func() {
		o.errorResponse(w, r, err, errorCode)
	}()

	param := ParseRequestParam(r)
	// get list uploads parameter
	prefix := param.GetVar(ParamPrefix)
	keyMarker := param.GetVar(ParamKeyMarker)
	delimiter := param.GetVar(ParamPartDelimiter)
	maxUploads := param.GetVar(ParamPartMaxUploads)
	uploadIdMarker := param.GetVar(ParamUploadIdMarker)

	var maxUploadsInt uint64
	if maxUploads == "" {
		maxUploadsInt = MaxUploads
	} else {
		maxUploadsInt, err = strconv.ParseUint(maxUploads, 10, 64)
		if err != nil {
			log.LogErrorf("listMultipartUploadsHandler: parse max uploads fail: requestID(%v) raw(%v) err(%v)",
				GetRequestID(r), maxUploads, err)
			errorCode = InvalidArgument
			return
		}
		if maxUploadsInt > MaxUploads {
			maxUploadsInt = MaxUploads
		}
	}

	if param.Bucket() == "" {
		errorCode = InvalidBucketName
		return
	}

	var vol *Volume
	if vol, err = o.getVol(param.Bucket()); err != nil {
		log.LogErrorf("listMultipartUploadsHandler: load volume fail: requestID(%v) vol(%v) err(%v)",
			GetRequestID(r), param.Bucket(), err)
		return
	}

	// QPS and Concurrency Limit
	rateLimit := o.AcquireRateLimiter()
	if err = rateLimit.AcquireLimitResource(vol.owner, param.apiName); err != nil {
		return
	}
	defer rateLimit.ReleaseLimitResource(vol.owner, param.apiName)

	// List multipart uploads
	start := time.Now()
	fsUploads, nextKeyMarker, nextUploadIdMarker, IsTruncated, prefixes, err := vol.ListMultipartUploads(prefix, delimiter, keyMarker, uploadIdMarker, maxUploadsInt)
	span.AppendTrackLog("part.l", start, err)
	if err != nil {
		log.LogErrorf("listMultipartUploadsHandler: list multipart uploads fail: requestID(%v) err(%v)",
			GetRequestID(r), err)
		return
	}

	uploads := NewUploads(fsUploads, param.AccessKey())

	commonPrefixes := make([]*CommonPrefix, 0)
	for _, prefix := range prefixes {
		commonPrefix := &CommonPrefix{
			Prefix: prefix,
		}
		commonPrefixes = append(commonPrefixes, commonPrefix)
	}

	listUploadsResult := ListUploadsResult{
		Bucket:             param.Bucket(),
		KeyMarker:          keyMarker,
		UploadIdMarker:     uploadIdMarker,
		NextKeyMarker:      nextKeyMarker,
		NextUploadIdMarker: nextUploadIdMarker,
		Delimiter:          delimiter,
		Prefix:             prefix,
		MaxUploads:         maxUploadsInt,
		IsTruncated:        IsTruncated,
		Uploads:            uploads,
		CommonPrefixes:     commonPrefixes,
	}
	response, err := MarshalXMLEntity(listUploadsResult)
	if err != nil {
		log.LogErrorf("listMultipartUploadsHandler: xml marshal result fail: requestID(%v) result(%v) err(%v)",
			GetRequestID(r), listUploadsResult, err)
		return
	}

	writeSuccessResponseXML(w, response)
	return
}

func determineCopyRange(copyRange string, fsize int64) (firstByte, copyLength int64, err *ErrorCode) {
	if copyRange == "" { // whole file
		return 0, fsize, nil
	}
	firstByte, lastByte, err := extractCopyRangeParam(copyRange)
	if err != nil {
		return
	}
	if !(0 <= firstByte && firstByte <= lastByte && lastByte < fsize) {
		err = InvalidArgument
		return
	}
	copyLength = lastByte + 1 - firstByte
	if copyLength > MaxPartCopySize {
		err = EntityTooLarge
		return
	}
	return
}

func extractCopyRangeParam(copRange string) (firstByte, lastByte int64, err *ErrorCode) {
	// copRange must use the form : bytes=first-last
	strs := strings.SplitN(copRange, "=", 2)
	if len(strs) < 2 {
		err = InvalidArgument
		return
	}
	byteRange := strings.SplitN(strs[1], "-", 2)
	if len(byteRange) < 2 {
		err = InvalidArgument
		return
	}
	firstByteStr, lastByteStr := byteRange[0], byteRange[1]
	firstByte, err1 := strconv.ParseInt(firstByteStr, 10, 64)
	lastByte, err2 := strconv.ParseInt(lastByteStr, 10, 64)
	if err1 != nil || err2 != nil {
		err = InvalidArgument
		return
	}
	return
}

type S3CopyPartResult struct {
	XMLName      xml.Name
	ETag         string `xml:"ETag"`
	LastModified string `xml:"LastModified"`
}

func NewS3CopyPartResult(etag, lastModified string) *S3CopyPartResult {
	return &S3CopyPartResult{
		XMLName: xml.Name{
			Space: S3Namespace,
			Local: "CopyPartResult",
		},
		ETag:         etag,
		LastModified: lastModified,
	}
}

func (s *S3CopyPartResult) String() string {
	b, _ := xml.Marshal(s)
	return string(b)
}
