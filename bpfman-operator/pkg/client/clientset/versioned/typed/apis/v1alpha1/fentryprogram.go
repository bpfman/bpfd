/*
Copyright 2023 The bpfman Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/bpfman/bpfman/bpfman-operator/apis/v1alpha1"
	scheme "github.com/bpfman/bpfman/bpfman-operator/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// FentryProgramsGetter has a method to return a FentryProgramInterface.
// A group's client should implement this interface.
type FentryProgramsGetter interface {
	FentryPrograms() FentryProgramInterface
}

// FentryProgramInterface has methods to work with FentryProgram resources.
type FentryProgramInterface interface {
	Create(ctx context.Context, fentryProgram *v1alpha1.FentryProgram, opts v1.CreateOptions) (*v1alpha1.FentryProgram, error)
	Update(ctx context.Context, fentryProgram *v1alpha1.FentryProgram, opts v1.UpdateOptions) (*v1alpha1.FentryProgram, error)
	UpdateStatus(ctx context.Context, fentryProgram *v1alpha1.FentryProgram, opts v1.UpdateOptions) (*v1alpha1.FentryProgram, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.FentryProgram, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.FentryProgramList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FentryProgram, err error)
	FentryProgramExpansion
}

// fentryPrograms implements FentryProgramInterface
type fentryPrograms struct {
	client rest.Interface
}

// newFentryPrograms returns a FentryPrograms
func newFentryPrograms(c *BpfmanV1alpha1Client) *fentryPrograms {
	return &fentryPrograms{
		client: c.RESTClient(),
	}
}

// Get takes name of the fentryProgram, and returns the corresponding fentryProgram object, and an error if there is any.
func (c *fentryPrograms) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.FentryProgram, err error) {
	result = &v1alpha1.FentryProgram{}
	err = c.client.Get().
		Resource("fentryprograms").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of FentryPrograms that match those selectors.
func (c *fentryPrograms) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.FentryProgramList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.FentryProgramList{}
	err = c.client.Get().
		Resource("fentryprograms").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested fentryPrograms.
func (c *fentryPrograms) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Resource("fentryprograms").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a fentryProgram and creates it.  Returns the server's representation of the fentryProgram, and an error, if there is any.
func (c *fentryPrograms) Create(ctx context.Context, fentryProgram *v1alpha1.FentryProgram, opts v1.CreateOptions) (result *v1alpha1.FentryProgram, err error) {
	result = &v1alpha1.FentryProgram{}
	err = c.client.Post().
		Resource("fentryprograms").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fentryProgram).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a fentryProgram and updates it. Returns the server's representation of the fentryProgram, and an error, if there is any.
func (c *fentryPrograms) Update(ctx context.Context, fentryProgram *v1alpha1.FentryProgram, opts v1.UpdateOptions) (result *v1alpha1.FentryProgram, err error) {
	result = &v1alpha1.FentryProgram{}
	err = c.client.Put().
		Resource("fentryprograms").
		Name(fentryProgram.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fentryProgram).
		Do(ctx).
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *fentryPrograms) UpdateStatus(ctx context.Context, fentryProgram *v1alpha1.FentryProgram, opts v1.UpdateOptions) (result *v1alpha1.FentryProgram, err error) {
	result = &v1alpha1.FentryProgram{}
	err = c.client.Put().
		Resource("fentryprograms").
		Name(fentryProgram.Name).
		SubResource("status").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(fentryProgram).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the fentryProgram and deletes it. Returns an error if one occurs.
func (c *fentryPrograms) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Resource("fentryprograms").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *fentryPrograms) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Resource("fentryprograms").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched fentryProgram.
func (c *fentryPrograms) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.FentryProgram, err error) {
	result = &v1alpha1.FentryProgram{}
	err = c.client.Patch(pt).
		Resource("fentryprograms").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
