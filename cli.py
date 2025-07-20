#!/usr/bin/env python3
"""
CLI interface for the nginx WAF AI system
"""

import asyncio
import click
import json
import sys
import os
from pathlib import Path

# Add src to path
current_dir = Path(__file__).parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

try:
    from traffic_collector import TrafficCollector
    from ml_engine import MLEngine, RealTimeProcessor
    from waf_rule_generator import WAFRuleGenerator, RuleOptimizer
    from nginx_manager import NginxManager, NginxNode
    from config import SystemConfig
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.pass_context
def cli(ctx, config):
    """Nginx WAF AI - Real-time machine learning WAF rule generator"""
    ctx.ensure_object(dict)
    
    if config:
        ctx.obj['config'] = SystemConfig.from_file(config)
    else:
        ctx.obj['config'] = SystemConfig.from_env()


@cli.command()
@click.option('--host', default='0.0.0.0', help='API host')
@click.option('--port', default=8000, help='API port')
@click.option('--debug/--no-debug', default=False, help='Debug mode')
@click.pass_context
def serve(ctx, host, port, debug):
    """Start the API server"""
    import uvicorn
    from src.main import app
    
    config = ctx.obj['config']
    uvicorn.run(
        app, 
        host=host or config.api_host,
        port=port or config.api_port,
        debug=debug or config.api_debug
    )


@cli.command()
@click.option('--training-data', '-d', required=True, help='Path to training data JSON file')
@click.option('--labels', '-l', help='Path to labels JSON file')
@click.option('--model-output', '-o', help='Path to save trained model')
@click.pass_context
def train(ctx, training_data, labels, model_output):
    """Train the ML models"""
    config = ctx.obj['config']
    
    # Load training data
    with open(training_data, 'r') as f:
        training_requests = json.load(f)
    
    # Load labels if provided
    labels_data = None
    if labels:
        with open(labels, 'r') as f:
            labels_data = json.load(f)
    
    # Initialize and train ML engine
    ml_engine = MLEngine()
    ml_engine.train_models(training_requests, labels_data)
    
    # Save model
    model_path = model_output or config.ml_model_path
    ml_engine.save_models(model_path)
    
    click.echo(f"Model trained and saved to {model_path}")


@cli.command()
@click.option('--nodes-config', '-n', required=True, help='Path to nginx nodes configuration JSON')
@click.option('--model-path', '-m', help='Path to trained model')
@click.option('--duration', '-d', default=60, help='Collection duration in seconds')
@click.pass_context
def collect(ctx, nodes_config, model_path, duration):
    """Collect traffic and detect threats"""
    config = ctx.obj['config']
    
    # Load nodes configuration
    with open(nodes_config, 'r') as f:
        nodes_data = json.load(f)
    
    # Create nginx nodes
    nodes = []
    for node_data in nodes_data:
        node = NginxNode(**node_data)
        nodes.append(node)
    
    # Initialize components
    traffic_collector = TrafficCollector([node.api_endpoint for node in nodes if node.api_endpoint])
    
    ml_engine = MLEngine()
    if model_path or config.ml_model_path:
        try:
            ml_engine.load_models(model_path or config.ml_model_path)
        except FileNotFoundError:
            click.echo("Warning: No trained model found. Run 'train' command first.")
            return
    
    real_time_processor = RealTimeProcessor(ml_engine, config.threat_threshold)
    
    async def collect_and_process():
        # Start traffic collection
        collection_task = asyncio.create_task(traffic_collector.start_collection())
        
        # Process for specified duration
        start_time = asyncio.get_event_loop().time()
        while (asyncio.get_event_loop().time() - start_time) < duration:
            # Get recent requests
            recent_requests = traffic_collector.get_recent_requests(100)
            
            if recent_requests:
                # Convert to dict format
                request_dicts = [req.to_dict() for req in recent_requests]
                
                # Detect threats
                threats = await real_time_processor.process_requests(request_dicts)
                
                if threats:
                    click.echo(f"Detected {len(threats)} threats:")
                    for threat in threats:
                        click.echo(f"  - {threat.threat_type}: {threat.threat_score:.3f}")
            
            await asyncio.sleep(5)
        
        # Stop collection
        traffic_collector.is_collecting = False
        collection_task.cancel()
        
        click.echo(f"Collection completed. Total requests: {len(traffic_collector.collected_requests)}")
    
    asyncio.run(collect_and_process())


@cli.command()
@click.option('--threats-file', '-t', required=True, help='Path to threats JSON file')
@click.option('--output', '-o', help='Output path for generated rules')
@click.pass_context
def generate_rules(ctx, threats_file, output):
    """Generate WAF rules from threats"""
    
    # Load threats data
    with open(threats_file, 'r') as f:
        threats_data = json.load(f)
    
    # Extract threat patterns
    threat_patterns = {}
    for threat in threats_data:
        threat_type = threat.get('threat_type', 'unknown')
        threat_patterns[threat_type] = threat_patterns.get(threat_type, 0) + 1
    
    # Generate rules
    rule_generator = WAFRuleGenerator()
    rules = rule_generator.generate_rules_from_threats(threats_data, threat_patterns)
    
    # Optimize rules
    rule_optimizer = RuleOptimizer()
    optimized_rules = rule_optimizer.optimize_rules(rules)
    
    # Generate nginx configuration
    nginx_config = rule_generator.generate_nginx_config(optimized_rules)
    
    # Output results
    if output:
        with open(output, 'w') as f:
            f.write(nginx_config)
        click.echo(f"Generated {len(optimized_rules)} rules and saved to {output}")
    else:
        click.echo(f"Generated {len(optimized_rules)} rules:")
        click.echo(nginx_config)


@cli.command()
@click.option('--nodes-config', '-n', required=True, help='Path to nginx nodes configuration JSON')
@click.option('--rules-file', '-r', required=True, help='Path to nginx rules configuration file')
@click.pass_context
def deploy(ctx, nodes_config, rules_file):
    """Deploy WAF rules to nginx nodes"""
    
    # Load nodes configuration
    with open(nodes_config, 'r') as f:
        nodes_data = json.load(f)
    
    # Create nginx nodes
    nodes = []
    for node_data in nodes_data:
        node = NginxNode(**node_data)
        nodes.append(node)
    
    # Load rules configuration
    with open(rules_file, 'r') as f:
        nginx_config = f.read()
    
    # Deploy to nodes
    nginx_manager = NginxManager(nodes)
    
    async def deploy_rules():
        deployment_results = await nginx_manager.deploy_rules_to_all_nodes(nginx_config)
        
        click.echo("Deployment results:")
        for node_id, success in deployment_results.items():
            status = "SUCCESS" if success else "FAILED"
            click.echo(f"  {node_id}: {status}")
    
    asyncio.run(deploy_rules())


@cli.command()
@click.option('--nodes-config', '-n', required=True, help='Path to nginx nodes configuration JSON')
@click.pass_context
def status(ctx, nodes_config):
    """Check status of nginx nodes"""
    
    # Load nodes configuration
    with open(nodes_config, 'r') as f:
        nodes_data = json.load(f)
    
    # Create nginx nodes
    nodes = []
    for node_data in nodes_data:
        node = NginxNode(**node_data)
        nodes.append(node)
    
    # Check status
    nginx_manager = NginxManager(nodes)
    
    async def check_status():
        cluster_status = await nginx_manager.get_cluster_status()
        
        click.echo(f"Cluster Status ({cluster_status['timestamp']}):")
        click.echo(f"  Total nodes: {cluster_status['total_nodes']}")
        click.echo(f"  Healthy nodes: {cluster_status['healthy_nodes']}")
        click.echo(f"  Unhealthy nodes: {cluster_status['unhealthy_nodes']}")
        
        click.echo("\nNode Details:")
        for node_id, status in cluster_status['node_details'].items():
            nginx_status = "UP" if status.get('nginx_running') else "DOWN"
            config_status = "VALID" if status.get('config_valid') else "INVALID"
            error = status.get('error', '')
            
            click.echo(f"  {node_id}: nginx={nginx_status}, config={config_status}")
            if error:
                click.echo(f"    Error: {error}")
    
    asyncio.run(check_status())


@cli.command()
@click.option('--config-file', '-c', help='Configuration file to generate')
@click.pass_context
def init_config(ctx, config_file):
    """Initialize configuration file"""
    config = ctx.obj['config']
    
    config_path = config_file or 'config/waf_ai_config.json'
    config.save_to_file(config_path)
    
    click.echo(f"Configuration saved to {config_path}")


if __name__ == '__main__':
    cli()
