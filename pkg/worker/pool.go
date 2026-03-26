package worker

import (
	"context"
	"sync"
)

// Job defines the work to be done
type Job struct {
	Path     string
	Priority int
}

// Result is the output of a Job execution
type Result struct {
	Path  string
	Err   error
	Value interface{}
}

// Pool represents the worker pool
type Pool struct {
	workers int
	jobs    chan Job
	results chan Result
	wg      sync.WaitGroup
	handler func(context.Context, string) (interface{}, error)
}

// NewPool creates a new worker pool
func NewPool(workers int, handler func(context.Context, string) (interface{}, error)) *Pool {
	return &Pool{
		workers: workers,
		jobs:    make(chan Job, workers*2),
		results: make(chan Result, workers*2),
		handler: handler,
	}
}

// Start spins up the workers
func (p *Pool) Start(ctx context.Context) {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(ctx)
	}
}

// worker listens for jobs and processes them
func (p *Pool) worker(ctx context.Context) {
	defer p.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job, ok := <-p.jobs:
			if !ok {
				return
			}
			val, err := p.handler(ctx, job.Path)
			select {
			case p.results <- Result{Path: job.Path, Value: val, Err: err}:
			case <-ctx.Done():
				return
			}
		}
	}
}

// Submit enqueues a job
func (p *Pool) Submit(job Job) {
	p.jobs <- job
}

// Results returns the results channel
func (p *Pool) Results() <-chan Result {
	return p.results
}

// Wait waits for workers to finish and closes the results channel
func (p *Pool) Wait() {
	close(p.jobs)
	p.wg.Wait()
	close(p.results)
}
