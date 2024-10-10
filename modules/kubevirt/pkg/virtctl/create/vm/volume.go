/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright the KubeVirt Authors.
 *
 */

package vm

import "k8s.io/apimachinery/pkg/api/resource"

type cloneVolume struct {
	Name      string             `param:"name"`
	Source    string             `param:"src"`
	BootOrder *uint              `param:"bootorder"`
	Size      *resource.Quantity `param:"size"`
}

type containerdiskVolume struct {
	Name      string `param:"name"`
	Source    string `param:"src"`
	BootOrder *uint  `param:"bootorder"`
}

type pvcVolume struct {
	Name      string `param:"name"`
	Source    string `param:"src"`
	BootOrder *uint  `param:"bootorder"`
}

type blankVolume struct {
	Name string             `param:"name"`
	Size *resource.Quantity `param:"size"`
}

type dataVolumeSourceBlank struct {
	Size *resource.Quantity `param:"size"`
	Type string             `param:"type"`
	Name string             `param:"name"`
}

type dataVolumeSourceGcs struct {
	SecretRef string             `param:"secretref"`
	URL       string             `param:"url"`
	Size      *resource.Quantity `param:"size"`
	Type      string             `param:"type"`
	Name      string             `param:"name"`
}

type dataVolumeSourceHttp struct {
	CertConfigMap      string             `param:"certconfigmap"`
	ExtraHeaders       []string           `param:"extraheaders"`
	SecretExtraHeaders []string           `param:"secretextraheaders"`
	SecretRef          string             `param:"secretref"`
	URL                string             `param:"url"`
	Size               *resource.Quantity `param:"size"`
	Type               string             `param:"type"`
	Name               string             `param:"name"`
}

type dataVolumeSourceImageIO struct {
	CertConfigMap string             `param:"certconfigmap"`
	DiskId        string             `param:"diskid"`
	SecretRef     string             `param:"secretref"`
	URL           string             `param:"url"`
	Size          *resource.Quantity `param:"size"`
	Type          string             `param:"type"`
	Name          string             `param:"name"`
}

type dataVolumeSourcePVC struct {
	Name   string             `param:"name"`
	Source string             `param:"src"`
	Size   *resource.Quantity `param:"size"`
	Type   string             `param:"type"`
}

type dataVolumeSourceRegistry struct {
	CertConfigMap string             `param:"certconfigmap"`
	ImageStream   string             `param:"imagestream"`
	PullMethod    string             `param:"pullmethod"`
	SecretRef     string             `param:"secretref"`
	URL           string             `param:"url"`
	Size          *resource.Quantity `param:"size"`
	Type          string             `param:"type"`
	Name          string             `param:"name"`
}

type dataVolumeSourceS3 struct {
	CertConfigMap string             `param:"certconfigmap"`
	SecretRef     string             `param:"secretref"`
	URL           string             `param:"url"`
	Size          *resource.Quantity `param:"size"`
	Type          string             `param:"type"`
	Name          string             `param:"name"`
}

type dataVolumeSourceVDDK struct {
	BackingFile  string             `param:"backingfile"`
	InitImageUrl string             `param:"initimageurl"`
	SecretRef    string             `param:"secretref"`
	ThumbPrint   string             `param:"thumbprint"`
	URL          string             `param:"url"`
	UUID         string             `param:"uuid"`
	Size         *resource.Quantity `param:"size"`
	Type         string             `param:"type"`
	Name         string             `param:"name"`
}

type dataVolumeSourceSnapshot struct {
	Name   string             `param:"name"`
	Source string             `param:"src"`
	Size   *resource.Quantity `param:"size"`
	Type   string             `param:"type"`
}
